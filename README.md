# Sentinel — Autonomous Security Alert Triage Agent

**Built by Mohit Kumar** — B.Tech CSE (final year), Amity University Rajasthan
| for the Xiarch Bharat Pvt Ltd — Agentic AI Engineer Intern assessment

Sentinel is an autonomous AI agent that triages security alerts the way a
junior SOC analyst would: it looks at the alert queue, digs into the logs,
checks suspicious IPs and hashes against public threat intelligence, decides
what each alert means, and writes an incident report — on its own, from a
single goal written in plain English.

Give it a goal like:

> "Triage all alerts in data/alerts.json and write an incident report"

…and it works through the job step by step, with almost no supervision.
You do not tell it *how* to triage. You tell it *what outcome you want*,
and it figures out the steps itself.

## Why this is an autonomous agent, not a script

A normal script follows rules its author wrote in advance:
`if severity == "critical": escalate`. Sentinel has **none of that**.
There is no `if/else` triage logic anywhere in the code — no hard-coded
responses, no predefined rules, no static outputs.

Instead, Sentinel reasons with a large language model (Google Gemini,
free tier) in a **ReAct loop**:

```
                    ┌──────────────────────────────────┐
                    │  GOAL (plain English)            │
                    │  "Triage all alerts and write    │
                    │   an incident report"            │
                    └──────────────┬───────────────────┘
                                   ▼
              ┌─────────────────────────────────────────┐
              │  PERCEIVE                               │
              │  Tools read the world: alerts, logs,    │
              │  IP lookups, threat-intel search        │
              └──────────────┬──────────────────────────┘
                             ▼
              ┌─────────────────────────────────────────┐
              │  REASON  (LLM — Gemini 2.0 Flash)       │
              │  "What do I know so far? What is the    │
              │   most useful next step? Which tool      │
              │   should I use, and with what input?"   │
              │  Answers as JSON: thought + action       │
              └──────────────┬──────────────────────────┘
                             ▼
              ┌─────────────────────────────────────────┐
              │  ACT                                     │
              │  Run the chosen tool, get an observation │
              └──────────────┬──────────────────────────┘
                             ▼
              ┌─────────────────────────────────────────┐
              │  OBSERVE + REFLECT                      │
              │  Add the observation to memory.          │
              │  Done? → finish. Otherwise loop back    │
              │  to REASON with everything learned.     │
              └─────────────────────────────────────────┘
```

The loop runs for at most 10 steps and stops **only when the LLM itself
decides the goal is done** and calls the `finish` tool. Every thought,
action and observation is printed live and saved to
`logs/agent_trace.json`, so you can audit exactly how the agent reasoned.

### What the LLM decides vs what the tools do

| Decided by the LLM (reasoning) | Done by tools (no decisions) |
|---|---|
| Which alert to look at first, and why | `read_alerts` — returns the alert queue as text |
| Whether a log check / IP lookup / intel search is needed | `read_log_file` — returns matching log lines |
| What a suspicious IP, hash or login pattern means | `check_ip` — returns country / ISP / ASN for an IP |
| How severe each alert is, and what to recommend | `search_threat_intel` — returns public intel snippets |
| What goes in the report, and when the job is done | `write_report` — writes the markdown file the LLM composed |

Tools only *observe* and *write*. They never judge, rank or conclude.
If you swap the LLM for a different model, the agent's behaviour
changes — because the reasoning lives in the model, not in the code.

## Project structure

```
xiarch-agentic-ai-agent/
├── main.py                     # CLI: --demo, --goal "...", or interactive
├── requirements.txt            # Only requests + python-dotenv
├── .env.example                # Copy to .env, add ONE free API key
├── .gitignore                  # Keeps .env, logs/ and reports/ out of git
├── README.md
├── sentinel/
│   ├── __init__.py
│   ├── llm.py                  # Gemini (free) first, OpenAI-compatible fallback
│   ├── tools.py                # 6 tools + registry the LLM chooses from
│   └── agent.py                # ReAct loop, memory, JSON retry, trace logging
├── data/
│   ├── alerts.json             # 6 realistic sample alerts
│   └── auth.log                # 28 log lines matching those alerts
├── reports/
│   └── sample_incident_report.md   # Example of a report the agent produces
├── logs/
│   └── agent_trace.json        # Created on each run (full reasoning trace)
└── tests/
    └── test_tools.py           # Tests that need no API key
```

## Setup — 3 steps

**Step 1 — Clone and enter the project**

```bash
git clone https://github.com/Mohit333707/xiarch-agentic-ai-agent.git
cd xiarch-agentic-ai-agent
```

(Or unzip the submitted ZIP and `cd` into it — same thing from here on.)

**Step 2 — Install dependencies**

```bash
pip install -r requirements.txt
```

That is the whole install: `requests` and `python-dotenv` only.
There is no LangChain or LangGraph — the ReAct loop is plain Python in
`sentinel/agent.py`, which keeps the install light and reliable.
Python 3.10 or newer is required.

**Step 3 — Get a free Gemini key (about 2 minutes)**

1. Go to **https://aistudio.google.com/app/apikey**
2. Sign in with a Google account and click **Create API key**.
3. Copy the key into a `.env` file:

```bash
cp .env.example .env
# then open .env and set:  GEMINI_API_KEY=your-key-here
```

No key? Sentinel will not fake it — running without a key prints this
same 2-minute guide and exits cleanly instead of crashing or falling
back to hard-coded answers. A Groq key (`GROQ_API_KEY`, also free) or an
OpenAI key (`OPENAI_API_KEY`) works as a fallback.

## How to run

**Demo — the default triage goal, no arguments needed:**

```bash
python main.py --demo
```

**Your own goal in plain English:**

```bash
python main.py --goal "Triage all alerts in data/alerts.json and write an incident report"
```

**Interactive mode — it asks you for a goal:**

```bash
python main.py
```

**More examples to try:**

```bash
# Only the critical and high alerts, shortest possible report
python main.py --goal "Check the critical and high severity alerts only, and write a short report to reports/critical_report.md"

# Investigate one alert in depth
python main.py --goal "Investigate alert ALT-1001 in detail: check the logs and the source IP, then write a short report"

# Give the agent more room (default is 10 steps)
python main.py --demo --max-steps 12
```

## Sample output

A run looks like this (shortened — the real trace has more steps):

```
[goal] Triage all alerts in data/alerts.json and write an incident report ...

--- Step 1 ---
Thought: I need to see what alerts are waiting before I can plan.
Action:  read_alerts {'limit': 10}
Observe: Found 6 alert(s) ...
  - [ALT-1004] critical | Malware hash detected ...

--- Step 2 ---
Thought: ALT-1004 is critical. I should check the log for that hash...
Action:  read_log_file {'search': 'e3b0c44298fc1c14'}

--- Step 3 ---
Thought: The file was quarantined, but I should check if this hash
  is known malware before I conclude.
Action:  search_threat_intel {'query': 'e3b0c44298fc1c149afbf4c8996fb924...'}

...

--- Step 8 ---
Thought: I have investigated all 6 alerts. Time to write the report.
Action:  write_report {'content': '# Incident Report ...', 'filename': 'incident_report.md'}

--- Step 9 ---
Thought: Report written, all alerts covered. Goal is done.
Action:  finish {'summary': 'Triaged 6 alerts ... report written.'}
Done:    Triaged 6 alerts ...

Trace saved to logs/agent_trace.json
```

After a run you will have two artefacts to show:

- `reports/incident_report.md` — the report the agent wrote.
- `logs/agent_trace.json` — every thought, action and observation,
  so anyone can check *how* it reached its conclusions.

A realistic example of the report is already in the repo:
`reports/sample_incident_report.md` (marked SAMPLE — it shows the
format and depth to expect, not a live run).

## Tests

The tests need **no API key** — they check the tools and the ReAct
JSON parsing with a fake LLM, so they run anywhere:

```bash
python -m pytest tests/ -v
```

If `pytest` is not installed, the same file also runs directly:

```bash
python tests/test_tools.py
```

What is covered: reading alerts, handling a bad/missing IP lookup,
writing a report file, and parsing the LLM's
`{"thought", "action", "action_input"}` JSON (including a fenced
```json block and a bad-JSON retry).

## Limitations — stated honestly

- **It needs an LLM key and internet.** Without a key it refuses to
  run (by design). Without internet, the IP / threat-intel tools
  return "unavailable" observations and the agent carries on with
  local evidence only — it says so in the report rather than guessing.
- **The LLM can be wrong.** It may misjudge an alert or pick a
  wasteful next step. That is why every step is logged: the trace
  is the audit trail, and a human should review the report before
  acting on a critical alert.
- **Sample data is synthetic.** The IPs use the `203.0.113.x` /
  `198.51.100.x` documentation ranges, the hash is a placeholder,
  and the names are invented. Nothing here is real personal data.
- **Free-tier limits apply.** Gemini's free tier has per-minute
  quotas; a run of ~10 steps is well inside them, but a very long
  run may hit a rate limit and stop with an error message.
- **No real remediation.** Sentinel investigates and reports. It
  does not block IPs, disable accounts or delete files — those
  actions need human approval in any real SOC.

## Future work

- A second agent that *acts* on the report (block IP / disable user)
  only after a human approves each action.
- Live log streaming instead of a static `auth.log` file.
- A Streamlit dashboard showing the trace live, step by step.
- Memory across runs: remember IPs already investigated so repeat
  alerts are triaged faster.
- Support for more alert sources (JSON, CSV, a SIEM webhook).

## Author

**Mohit Kumar** — B.Tech CSE, Amity University Rajasthan (Class of 2027), CGPA 7.52
GitHub: https://github.com/Mohit333707
Skills: Python, RAG, ML, Streamlit

Built from scratch for the Xiarch Bharat Agentic AI Engineer Intern
assessment (deadline 26 Nov 2026). No code was copied from public
repositories; the ReAct loop, tools and LLM layer were written for
this project.
