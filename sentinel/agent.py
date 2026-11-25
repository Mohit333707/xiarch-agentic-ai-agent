"""
ReAct agent loop for Sentinel.

Perceive -> Reason (LLM) -> Act (tool) -> Observe -> Reflect, repeat.

The LLM is the only thing that reasons here. This file is just the
loop around it:
    1. Build a prompt: goal + available tools + everything seen so far.
    2. Ask the LLM for ONE next step as JSON:
           {"thought": "...", "action": "...", "action_input": {...}}
    3. Run that tool, feed the observation back, and repeat.
    4. Stop only when the LLM itself calls the `finish` tool,
       or when max_steps is reached.

There are no triage rules in this file -- no "if severity == high
then ..." logic. Severity, priority and next steps are all decided
by the LLM from the evidence the tools return.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .tools import TOOLS, run_tool, tool_descriptions

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

SYSTEM_PROMPT = """You are Sentinel, an autonomous security-alert triage agent.
Your job: achieve the user's goal with minimal supervision, using tools.

HOW YOU WORK (ReAct):
- Think step by step, then take exactly ONE action per reply.
- Your reply must be ONLY a JSON object, no other text:
    {"thought": "<your reasoning in 1-3 sentences>",
     "action": "<one tool name from the list below>",
     "action_input": {<arguments for that tool>}}
- Never invent tool names or alert data. If you need facts, use a tool.
- Investigate before you report: read the alerts, check the logs,
  look up suspicious IPs / hashes with the intel tools, then write
  the report, then call finish.
- Call "finish" ONLY when the goal is fully done. Its "summary"
  should say what you did and the outcome in one short paragraph.

TOOLS YOU CAN USE:
{tools}

GOAL:
{goal}

HISTORY (your previous thoughts, actions and what the tools returned):
{history}

Reply with ONLY the JSON object for your next step.
"""

MAX_OBSERVATION_CHARS = 3000  # truncate long observations in the prompt only


def extract_json(text: str) -> dict:
    """Pull a JSON object out of the LLM's reply.

    Accepts raw JSON, a ```json fenced block, or JSON with a little
    surrounding text. Raises ValueError if nothing parses.
    """
    if not text or not text.strip():
        raise ValueError("empty reply from LLM")
    cleaned = text.strip()
    # Strip a markdown fence if the model wrapped its answer in one.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1)
    else:
        # Otherwise take the first {...} block.
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError(f"no JSON object found in reply: {text[:300]!r}")
        cleaned = cleaned[start : end + 1]
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM reply JSON was not an object")
    if "thought" not in parsed or "action" not in parsed:
        raise ValueError(
            "LLM reply JSON must contain 'thought' and 'action' keys"
        )
    parsed.setdefault("action_input", {})
    if not isinstance(parsed["action_input"], dict):
        raise ValueError("'action_input' must be a JSON object")
    return parsed


class SentinelAgent:
    """Runs the ReAct loop until the LLM calls finish or steps run out."""

    def __init__(self, llm, max_steps: int = 10):
        self.llm = llm  # any object with a .call(prompt: str) -> str method
        self.max_steps = max_steps
        self.steps: list[dict] = []

    # -- main loop ------------------------------------------------------
    def run(self, goal: str) -> dict:
        print(f"\n[goal] {goal}\n")
        final_summary = ""
        finished = False

        for step_no in range(1, self.max_steps + 1):
            # NOTE: plain .replace(), not str.format() -- the prompt
            # contains literal {"thought": ...} braces that .format()
            # would try to interpret as placeholders (KeyError).
            prompt = (
                SYSTEM_PROMPT.replace("{tools}", tool_descriptions())
                .replace("{goal}", goal)
                .replace("{history}", self._format_history())
            )
            try:
                decision = self._ask_with_retries(prompt)
            except RuntimeError as exc:
                # LLM itself failed (network / API error) -- stop cleanly.
                print(f"\n[!] LLM call failed at step {step_no}: {exc}")
                self.steps.append(
                    {"step": step_no, "error": str(exc), "action": None}
                )
                break

            thought = decision["thought"]
            action = decision["action"]
            action_input = decision.get("action_input") or {}

            print(f"--- Step {step_no} ---")
            print(f"Thought: {thought}")
            print(f"Action:  {action} {action_input}")

            if action == "finish":
                final_summary = run_tool("finish", action_input)
                self.steps.append(
                    {
                        "step": step_no,
                        "thought": thought,
                        "action": action,
                        "action_input": action_input,
                        "observation": final_summary,
                    }
                )
                print(f"Done:    {final_summary}")
                finished = True
                break

            observation = run_tool(action, action_input)
            print(f"Observe: {observation[:500]}")
            if len(observation) > 500:
                print("         ... (observation truncated in console; full text in trace)")
            print()

            self.steps.append(
                {
                    "step": step_no,
                    "thought": thought,
                    "action": action,
                    "action_input": action_input,
                    "observation": observation,
                }
            )

        if not finished:
            final_summary = (
                f"Stopped after {self.max_steps} steps without the LLM "
                "calling finish. The trace in logs/agent_trace.json shows "
                "how far the investigation got."
            )
            print(f"\n[!] {final_summary}")

        trace = {
            "goal": goal,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "max_steps": self.max_steps,
            "finished": finished,
            "final_summary": final_summary,
            "steps": self.steps,
        }
        trace_path = self._save_trace(trace)
        print(f"\nTrace saved to {trace_path}")
        return {"finished": finished, "final_summary": final_summary,
                "steps": self.steps, "trace_path": str(trace_path)}

    # -- helpers --------------------------------------------------------
    def _ask_with_retries(self, prompt: str, max_retries: int = 2) -> dict:
        """Ask the LLM for a JSON step; on bad JSON, ask it to fix it.

        Up to `max_retries` correction attempts. If the LLM still does
        not return valid JSON, raise RuntimeError (the run stops, but
        the trace collected so far is still saved by the caller).
        """
        current_prompt = prompt
        last_error = ""
        for attempt in range(max_retries + 1):
            raw = self.llm.call(current_prompt)
            try:
                return extract_json(raw)
            except ValueError as exc:
                last_error = str(exc)
                print(
                    f"[!] Step reply was not valid JSON (attempt "
                    f"{attempt + 1}/{max_retries + 1}): {exc}. "
                    "Asking the LLM to retry with correct JSON."
                )
                current_prompt = (
                    prompt
                    + "\n\nYour last reply was not valid JSON: "
                    + last_error
                    + "\nReply again with ONLY a JSON object like "
                    '{"thought": "...", "action": "...", "action_input": {...}}.'
                )
        raise RuntimeError(
            f"LLM did not return valid JSON after {max_retries + 1} attempts: "
            f"{last_error}"
        )

    def _format_history(self) -> str:
        if not self.steps:
            return "(no steps yet -- this is your first action)"
        parts = []
        for s in self.steps:
            if s.get("error"):
                parts.append(f"Step {s['step']}: ERROR: {s['error']}")
                continue
            obs = str(s.get("observation", ""))[:MAX_OBSERVATION_CHARS]
            parts.append(
                f"Step {s['step']}:\n"
                f"  Thought: {s.get('thought', '')}\n"
                f"  Action: {s.get('action', '')} {s.get('action_input', {})}\n"
                f"  Observation: {obs}"
            )
        return "\n".join(parts)

    def _save_trace(self, trace: dict) -> Path:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = LOGS_DIR / "agent_trace.json"
        path.write_text(json.dumps(trace, indent=2), encoding="utf-8")
        return path
