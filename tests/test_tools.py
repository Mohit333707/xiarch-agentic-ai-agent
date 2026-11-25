"""Tests for Sentinel -- no LLM API key needed.

Run with:
    python -m pytest tests/ -v
or, if pytest is not installed, directly:
    python tests/test_tools.py

The fake-LLM tests below live ONLY in this test file. They exist to
prove the ReAct JSON parsing works; the real agent code never uses
a fake or hard-coded LLM.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the project root importable whether run via pytest or directly.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.agent import SentinelAgent, extract_json  # noqa: E402
from sentinel.tools import check_ip, read_alerts, run_tool, write_report  # noqa: E402


# --- tools ---------------------------------------------------------------

def test_read_alerts_returns_six_alerts():
    text = read_alerts()
    assert "Found 6 alert(s)" in text
    for alert_id in ("ALT-1001", "ALT-1002", "ALT-1003",
                     "ALT-1004", "ALT-1005", "ALT-1006"):
        assert alert_id in text, f"{alert_id} missing from read_alerts output"


def test_read_alerts_limit_is_respected():
    text = read_alerts(limit=2)
    assert "ALT-1001" in text and "ALT-1002" in text
    assert "ALT-1003" not in text


def test_read_alerts_matches_data_file():
    alerts = json.loads((PROJECT_ROOT / "data" / "alerts.json").read_text())
    assert len(alerts) == 6
    types = {a["type"] for a in alerts}
    assert "SSH brute-force" in types and "Malware hash detected" in types


def test_check_ip_rejects_bad_input():
    assert "does not look like a valid IPv4" in check_ip("not-an-ip")
    assert "needs an IP address" in check_ip("")


def test_check_ip_returns_text_not_exception():
    # No network in a test sandbox is fine: the tool must return an
    # "unavailable" observation, never raise. With network it returns
    # the lookup. Either way the result is a string mentioning the IP.
    result = check_ip("8.8.8.8")
    assert isinstance(result, str) and len(result) > 0
    assert "8.8.8.8" in result


def test_write_report_creates_markdown(tmp_path=None):
    # Write to the real reports/ dir, then clean up after ourselves.
    out = write_report("# Test report\n\nHello.", filename="_test_report.md")
    path = PROJECT_ROOT / "reports" / "_test_report.md"
    assert "Report written to" in out
    assert path.exists()
    assert "# Test report" in path.read_text(encoding="utf-8")
    path.unlink()


def test_run_tool_unknown_tool_returns_error_observation():
    result = run_tool("does_not_exist", {})
    assert "unknown tool" in result.lower()
    assert "read_alerts" in result  # it helpfully lists what IS available


# --- ReAct JSON parsing (fake LLM only in this test file) -----------------

def test_extract_json_plain():
    parsed = extract_json(
        '{"thought": "Read the alerts first.", '
        '"action": "read_alerts", "action_input": {"limit": 5}}'
    )
    assert parsed["thought"] == "Read the alerts first."
    assert parsed["action"] == "read_alerts"
    assert parsed["action_input"] == {"limit": 5}


def test_extract_json_fenced_block():
    parsed = extract_json(
        "Here is my step:\n```json\n"
        '{"thought": "Check the log.", "action": "read_log_file", '
        '"action_input": {"search": "root"}}\n```'
    )
    assert parsed["action"] == "read_log_file"
    assert parsed["action_input"]["search"] == "root"


def test_extract_json_rejects_garbage():
    try:
        extract_json("I think we should look at the alerts, maybe?")
    except ValueError:
        return  # expected
    raise AssertionError("extract_json should raise ValueError on non-JSON")


class FakeLLM:
    """A stub LLM for tests only -- returns canned JSON replies in order.

    This is NOT part of the agent. It only proves the loop can drive
    tools from JSON decisions and stop on `finish`.
    """

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def call(self, prompt: str) -> str:
        reply = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        return reply


def test_agent_loop_with_fake_llm_writes_report_and_trace():
    fake = FakeLLM([
        '{"thought": "Read the alerts.", "action": "read_alerts", '
        '"action_input": {"limit": 6}}',
        '{"thought": "I have the alerts; write a short report.", '
        '"action": "write_report", "action_input": '
        '{"content": "# Test Incident Report\\n\\nFake-LLM triage test.", '
        '"filename": "_test_agent_report.md"}}',
        '{"thought": "Report written, goal is done.", '
        '"action": "finish", "action_input": '
        '{"summary": "Triaged alerts in test and wrote the report."}}',
    ])
    agent = SentinelAgent(fake, max_steps=10)
    result = agent.run("Test goal: triage alerts and write a report.")

    assert result["finished"] is True
    assert "Triaged alerts in test" in result["final_summary"]
    assert len(result["steps"]) == 3
    assert result["steps"][0]["action"] == "read_alerts"

    report = PROJECT_ROOT / "reports" / "_test_agent_report.md"
    assert report.exists() and "Test Incident Report" in report.read_text()
    report.unlink()

    trace_path = Path(result["trace_path"])
    assert trace_path.exists()
    trace = json.loads(trace_path.read_text())
    assert trace["finished"] is True and len(trace["steps"]) == 3


def test_agent_retries_bad_json_then_continues():
    fake = FakeLLM([
        "This is not JSON at all, just words.",
        '{"thought": "OK, proper JSON now.", "action": "finish", '
        '"action_input": {"summary": "Done after a retry."}}',
    ])
    agent = SentinelAgent(fake, max_steps=5)
    result = agent.run("Test goal: finish after one bad reply.")
    assert result["finished"] is True
    assert fake.calls == 2  # one bad reply + one good retry


# --- run directly without pytest ------------------------------------------
if __name__ == "__main__":
    tests = [
        test_read_alerts_returns_six_alerts,
        test_read_alerts_limit_is_respected,
        test_read_alerts_matches_data_file,
        test_check_ip_rejects_bad_input,
        test_check_ip_returns_text_not_exception,
        test_write_report_creates_markdown,
        test_run_tool_unknown_tool_returns_error_observation,
        test_extract_json_plain,
        test_extract_json_fenced_block,
        test_extract_json_rejects_garbage,
        test_agent_loop_with_fake_llm_writes_report_and_trace,
        test_agent_retries_bad_json_then_continues,
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print(f"FAIL {test.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
