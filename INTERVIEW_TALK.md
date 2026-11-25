# How to explain Sentinel in 1 minute — for the interview

Say this in simple English. Slow, one line at a time.

## The 1-minute talk

> "Sir, I built Sentinel, an autonomous security alert triage agent.
>
> You give it one goal in plain English, for example — triage all alerts
> and write an incident report.
>
> First, it perceives. It reads the alerts and the logs with its tools.
>
> Then, it reasons. It does not follow hard-coded rules. In every step,
> the LLM thinks — what do I know so far, what is the most useful next
> step — and it picks a tool by itself.
>
> Then, it acts. It checks the log, checks the IP, searches threat
> intelligence, and finally writes the report.
>
> It repeats this loop — perceive, reason, act, observe — for up to
> 10 steps, and it stops only when the LLM itself decides the goal is
> done. Every thought, action and observation is saved in a trace file,
> so you can see how it reasoned."

## If they ask: "Is this not just a script?"

> "No, sir. A script follows if-else rules written by me. Sentinel has
> no if-else triage logic. The LLM decides which alert to check first,
> whether an IP check is needed, how severe an alert is, and what to
> write in the report. Tools only return facts. All decisions are made
> by the LLM. If I change the model, the behaviour changes."

## If they ask: "What tools does it have?"

> "Six tools — read_alerts, read_log_file, search_threat_intel,
> check_ip, write_report, and finish. The LLM chooses the tool and
> the input every step."

## If they ask: "What if the LLM is wrong?"

> "That can happen, sir. That is why every step is logged in
> logs/agent_trace.json. A human should review the report before
> acting on a critical alert. Sentinel only investigates and reports —
> it does not block IPs or disable accounts."

## Demo line (say before you run it)

> "I will run `python main.py --demo`. It needs only a free Gemini
> key in the .env file. You will see each thought and action live,
> and at the end it writes reports/incident_report.md."
