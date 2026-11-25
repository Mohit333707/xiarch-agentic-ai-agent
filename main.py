#!/usr/bin/env python3
"""
Sentinel -- autonomous security-alert triage agent.

Run it:
    python main.py --demo
        Runs the default goal: triage every alert in data/alerts.json
        and write an incident report to reports/incident_report.md.

    python main.py --goal "Triage all alerts in data/alerts.json and write an incident report"
        Run with your own goal in plain English.

    python main.py
        Interactive mode -- asks you for a goal.

    python main.py --goal "..." --max-steps 12
        Allow up to 12 reasoning steps (default 10).

Setup (once):
    pip install -r requirements.txt
    cp .env.example .env        # then put your free Gemini key in .env

Sentinel reasons with an LLM (Google Gemini free tier first). It has
no hard-coded triage rules -- if no API key is set it exits with a
helpful message instead of guessing. See README.md.
"""

from __future__ import annotations

import argparse
import sys

from sentinel.agent import SentinelAgent
from sentinel.llm import LLMClient, NoAPIKeyError, helpful_no_key_message

DEFAULT_GOAL = (
    "Triage all alerts in data/alerts.json and write an incident report "
    "to reports/incident_report.md. For each alert, check the logs and "
    "any suspicious IP or hash with the threat-intel tools, decide its "
    "severity and what should be done next, then write one clear report "
    "covering all alerts and finish."
)

BANNER = r"""
  ____             _   _               _
 / ___|  ___ _ __ | |_(_)_ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ___) |  __/ | | | |_| | | | |  __/ |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|

  Autonomous Security Alert Triage Agent
  Perceive -> Reason (LLM) -> Act (tools) -> Observe -> Reflect
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sentinel -- autonomous security-alert triage agent."
    )
    parser.add_argument(
        "--goal",
        type=str,
        default=None,
        help="Goal in plain English, e.g. 'Triage all alerts and write a report'.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the default triage goal (same as --goal with the default text).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=10,
        help="Maximum reasoning steps before stopping (default: 10).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    args = parse_args(argv)

    if args.demo:
        goal = DEFAULT_GOAL
    elif args.goal:
        goal = args.goal.strip()
    else:
        # Interactive mode.
        print("No goal given -- interactive mode.")
        print("Example: Triage all alerts in data/alerts.json and write an incident report")
        try:
            goal = input("\nYour goal for Sentinel: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled. Goodbye!")
            return 0
        if not goal:
            print("No goal entered -- running the demo goal instead.")
            goal = DEFAULT_GOAL

    if args.max_steps < 1:
        print("Error: --max-steps must be at least 1.")
        return 2

    # The LLM is created here, before any work starts. If no key is
    # configured this raises NoAPIKeyError -- handled below with a
    # clean message and exit code 2, NOT a traceback.
    try:
        llm = LLMClient()
    except NoAPIKeyError:
        print(helpful_no_key_message())
        return 2
    except Exception as exc:  # e.g. bad .env value -- still no traceback
        print(f"\nCould not set up the LLM client: {exc}")
        return 2

    print(f"LLM: {llm.provider} / {llm.model}  |  max steps: {args.max_steps}")

    agent = SentinelAgent(llm, max_steps=args.max_steps)
    try:
        result = agent.run(goal)
    except RuntimeError as exc:
        print(f"\n[!] Agent stopped: {exc}")
        print("    Partial trace (if any) is in logs/agent_trace.json -- "
              "check it, fix the cause, and run again.")
        return 1

    print("\n" + ("=" * 60))
    if result["finished"]:
        print("Finished. " + result["final_summary"])
    else:
        print("Stopped before finishing. " + result["final_summary"])
    print("=" * 60)
    return 0 if result["finished"] else 1


if __name__ == "__main__":
    sys.exit(main())
