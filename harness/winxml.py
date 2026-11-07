"""Windows event XML lines (Splunk attack_data `XmlWinEventLog` and Sysmon for Linux) -> harness events.

Splunk attack_data stores Sysmon as one `<Event>...</Event>` XML document per line, the
form Splunk's XmlWinEventLog sourcetype keeps (ADR 012). This module turns each line into
the shape the rest of the harness already handles:

- Windows channels -> the flattened NXLog-style dict OTRF uses (`Channel`, `EventID`,
  `@timestamp`, `Hostname`, `SourceName` plus one key per EventData field), so
  `mapping.to_sentinel` builds the same `Event` / `SecurityEvent` row as for OTRF data.
- Sysmon for Linux (`Linux-Sysmon/Operational`) -> a `Syslog` row whose `SyslogMessage`
  is the XML line unchanged, which is how Microsoft's ASIM parser
  `ASimProcessCreateLinuxSysmon` (Azure-Sentinel repo, commit c0c2dc2) expects it:
  `Syslog | where SyslogMessage has_all ('<Provider Name="Linux-Sysmon"', '<EventID>1</EventID>')`.
  `ProcessName` is set to "sysmon" and `Facility` to "user"; neither is read by the
  rules and neither was checked against a live agent.

What is approximated: the System block other than provider, event id, time, channel and
computer is dropped; Syslog's other columns stay empty. Field values are copied unchanged.
Text that is not an XML event is skipped.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

LINUX_SYSMON_CHANNEL = "Linux-Sysmon/Operational"


def _strip(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_line(line: str) -> dict | None:
    """One XML event document -> harness event dict, or None if it is not an event."""
    line = line.strip()
    if not line.startswith("<Event"):
        return None
    root = ET.fromstring(line)
    system = {}
    data = {}
    for child in root:
        name = _strip(child.tag)
        if name == "System":
            for item in child:
                system[_strip(item.tag)] = item
        elif name == "EventData":
            for item in child:
                if item.get("Name"):
                    data[item.get("Name")] = item.text or ""
    channel = system["Channel"].text if "Channel" in system else ""
    when = system["TimeCreated"].get("SystemTime") if "TimeCreated" in system else None
    computer = system["Computer"].text if "Computer" in system else ""
    if channel == LINUX_SYSMON_CHANNEL:
        return {"Type": "Syslog", "TimeGenerated": when, "Computer": computer, "HostName": computer,
                "Facility": "user", "ProcessName": "sysmon", "SyslogMessage": line}
    event = {key: value for key, value in data.items()}
    event.update({
        "@timestamp": when,
        "Channel": channel,
        "EventID": int(system["EventID"].text),
        "Hostname": computer,
        "SourceName": system["Provider"].get("Name") if "Provider" in system else "",
    })
    return event


def read(folder: Path) -> list[dict]:
    """Every XML event line of every *.log file in a dataset folder."""
    events = []
    for path in sorted(folder.glob("*.log")):
        # One event per line, except where a field holds a newline (a command line
        # with an embedded line break), so split on the closing tag instead of on lines.
        for chunk in path.read_text(encoding="utf-8").split("</Event>"):
            if chunk.strip():
                event = parse_line(chunk + "</Event>")
                if event is not None:
                    events.append(event)
    return events
