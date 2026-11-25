"""
Tools for Sentinel.

A tool is the agent's hands: it can *observe* the world (read alerts,
read logs, look up an IP, search threat intel) and *act* on it (write
a report). Tools never decide anything themselves -- they only return
observations as text. Every decision about *which* tool to use next,
and what the observation means, is made by the LLM in agent.py.

All network tools degrade gracefully when offline: they return a short
"unavailable" observation so the LLM can carry on with local evidence
instead of the whole run crashing.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"

# --- tool implementations --------------------------------------------


def read_alerts(limit: int = 10) -> str:
    """Read the security alerts queue from data/alerts.json."""
    path = DATA_DIR / "alerts.json"
    try:
        alerts = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return f"ERROR: alert file not found at {path}."
    except json.JSONDecodeError as exc:
        return f"ERROR: alerts.json is not valid JSON: {exc}"

    if not isinstance(alerts, list):
        return "ERROR: alerts.json should contain a list of alerts."
    if not alerts:
        return "No alerts in the queue."

    lines = [f"Found {len(alerts)} alert(s) (showing up to {limit}):"]
    for alert in alerts[: int(limit)]:
        lines.append(
            f"- [{alert.get('id', '?')}] {alert.get('severity', '?')} | "
            f"{alert.get('type', '?')} | {alert.get('timestamp', '?')} | "
            f"user={alert.get('user', '?')} source_ip={alert.get('source_ip', '?')} | "
            f"{alert.get('description', '')}"
        )
    return "\n".join(lines)


def read_log_file(lines: int = 30, search: str = "") -> str:
    """Read data/auth.log. Pass `search` to show only matching lines."""
    path = DATA_DIR / "auth.log"
    try:
        all_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return f"ERROR: log file not found at {path}."

    if search:
        needle = search.lower()
        all_lines = [line for line in all_lines if needle in line.lower()]
        if not all_lines:
            return f"No log lines matched '{search}'."

    shown = all_lines[-int(lines):] if int(lines) > 0 else all_lines
    header = f"auth.log -- showing {len(shown)} line(s)"
    if search:
        header += f" matching '{search}'"
    return header + ":\n" + "\n".join(shown)


def search_threat_intel(query: str) -> str:
    """Search public threat intel via DuckDuckGo HTML (free, no key).

    Returns short text snippets. If the network is unavailable, returns
    a clear 'unavailable' observation instead of raising.
    """
    if not query or not query.strip():
        return "ERROR: search_threat_intel needs a non-empty query string."
    try:
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query.strip()},
            headers={"User-Agent": "Mozilla/5.0 Sentinel-Triage-Agent"},
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return (
            "Threat-intel search unavailable (no network or DuckDuckGo "
            f"unreachable: {exc}). Continue using local alerts/logs only."
        )

    # The HTML endpoint returns simple result blocks; strip tags to text.
    results = re.findall(
        r'class="result__a"[^>]*>(.*?)</a>.*?(?:class="result__snippet"[^>]*>(.*?)</a>)?',
        resp.text,
        flags=re.DOTALL,
    )
    if not results:
        return f"No public threat-intel results found for '{query}'."

    lines = [f"Threat-intel results for '{query}':"]
    for title_html, snippet_html in results[:5]:
        title = html.unescape(re.sub(r"<[^>]+>", "", title_html)).strip()
        snippet = html.unescape(re.sub(r"<[^>]+>", "", snippet_html or "")).strip()
        lines.append(f"- {title}" + (f" -- {snippet}" if snippet else ""))
    return "\n".join(lines)


def check_ip(ip: str) -> str:
    """Look up an IP with the free ip-api.com service (no key).

    Returns country / city / ISP / ASN when available.
    """
    if not ip or not ip.strip():
        return "ERROR: check_ip needs an IP address string."
    ip = ip.strip()
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return f"'{ip}' does not look like a valid IPv4 address."

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,query"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return (
            f"IP lookup unavailable (no network or ip-api.com unreachable: "
            f"{exc}). Continue using local evidence only."
        )
    except ValueError:
        return "IP lookup returned a response that was not valid JSON."

    if data.get("status") != "success":
        return f"IP lookup failed for {ip}: {data.get('message', 'unknown error')}"
    return (
        f"IP {data.get('query')}: country={data.get('country', '?')}, "
        f"region={data.get('regionName', '?')}, city={data.get('city', '?')}, "
        f"ISP={data.get('isp', '?')}, org={data.get('org', '?')}, "
        f"ASN={data.get('as', '?')}"
    )


def write_report(content: str, filename: str = "incident_report.md") -> str:
    """Write the agent's incident report (markdown) to reports/."""
    if not content or not content.strip():
        return "ERROR: write_report needs non-empty markdown content."
    # Keep reports inside reports/ -- reject paths that escape it.
    safe_name = Path(filename).name or "incident_report.md"
    if not safe_name.endswith(".md"):
        safe_name += ".md"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / safe_name
    path.write_text(content, encoding="utf-8")
    return f"Report written to {path} ({len(content)} characters)."


def finish(summary: str = "") -> str:
    """Signal the agent loop to stop. `summary` is the final outcome."""
    return summary or "Task finished."


# --- registry: what the LLM is allowed to choose from -----------------
# The agent builds its prompt from this registry, so adding a new tool
# here automatically makes it visible (and usable) to the LLM.

TOOLS = {
    "read_alerts": {
        "function": read_alerts,
        "description": (
            "Read the security alerts queue from data/alerts.json. "
            "Args: {\"limit\": <number of alerts, default 10>}. "
            "Use first to see what needs triaging."
        ),
    },
    "read_log_file": {
        "function": read_log_file,
        "description": (
            "Read data/auth.log (authentication / SSH log lines). "
            "Args: {\"lines\": <number, default 30>, "
            "\"search\": \"<optional text to filter lines, e.g. an IP or username>\"}. "
            "Use to corroborate an alert with raw log evidence."
        ),
    },
    "search_threat_intel": {
        "function": search_threat_intel,
        "description": (
            "Search public threat intelligence (DuckDuckGo, free, no key). "
            "Args: {\"query\": \"<e.g. 'SSH brute force 203.0.113.45' or a malware hash>\"}. "
            "Use to check whether an IP, hash or phishing domain is known-bad."
        ),
    },
    "check_ip": {
        "function": check_ip,
        "description": (
            "Look up an IP address location / ISP / ASN via ip-api.com (free, no key). "
            "Args: {\"ip\": \"<IPv4 address, e.g. 203.0.113.45>\"}. "
            "Use to check where a suspicious login or scan came from."
        ),
    },
    "write_report": {
        "function": write_report,
        "description": (
            "Write the final incident report (markdown) to reports/. "
            "Args: {\"content\": \"<full markdown report>\", "
            "\"filename\": \"incident_report.md\"}. "
            "Use only after investigating, when you are ready to report."
        ),
    },
    "finish": {
        "function": finish,
        "description": (
            "Stop. Call this ONLY when the goal is fully done (report "
            "written if one was asked for). "
            "Args: {\"summary\": \"<one short paragraph: what was done and the outcome>\"}."
        ),
    },
}


def tool_descriptions() -> str:
    """One-line-per-tool text pasted into the LLM's prompt."""
    return "\n".join(
        f"- {name}: {spec['description']}" for name, spec in TOOLS.items()
    )


def run_tool(name: str, action_input: dict | None) -> str:
    """Run a registered tool by name. Unknown names return an observation
    (not an exception) so the LLM can correct itself next step."""
    spec = TOOLS.get(name)
    if spec is None:
        return (
            f"ERROR: unknown tool '{name}'. Available tools: "
            f"{', '.join(TOOLS)}. Pick one of these."
        )
    try:
        return str(spec["function"](**(action_input or {})))
    except TypeError as exc:
        return (
            f"ERROR: wrong arguments for tool '{name}': {exc}. "
            f"Check the tool description and retry with correct arguments."
        )
    except Exception as exc:  # a tool must never crash the agent loop
        return f"ERROR: tool '{name}' failed: {exc}"
