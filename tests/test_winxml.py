"""harness/winxml.py: Windows event XML lines (Splunk XmlWinEventLog) -> harness events (ADR 012)."""

from harness import mapping, winxml

WINDOWS = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
           "<EventID>1</EventID><TimeCreated SystemTime='2026-11-06T12:00:00.000000000Z'/>"
           "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>host1</Computer></System>"
           "<EventData><Data Name='Image'>C:\\Windows\\notepad.exe</Data>"
           "<Data Name='CommandLine'>notepad.exe a.txt\nsecond line</Data>"
           "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data></EventData></Event>")
LINUX = ('<Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>'
         '<EventID>1</EventID><TimeCreated SystemTime="2026-11-06T12:00:01.000000000Z"/>'
         '<Channel>Linux-Sysmon/Operational</Channel><Computer>host2</Computer></System>'
         '<EventData><Data Name="Image">/usr/bin/ls</Data></EventData></Event>')


def test_windows_event_becomes_sysmon_event_row():
    event = winxml.parse_line(WINDOWS)
    assert event["EventID"] == 1 and event["Hostname"] == "host1"
    assert event["SourceName"] == "Microsoft-Windows-Sysmon"
    table, row = mapping.to_sentinel(event)
    assert table == "Event"
    assert row["Source"] == "Microsoft-Windows-Sysmon" and row["EventID"] == 1
    assert "<Data Name=\"Image\">C:\\Windows\\notepad.exe</Data>" in row["EventData"]
    assert row["TimeGenerated"] == "2026-11-06T12:00:00.000000000Z"


def test_linux_sysmon_becomes_syslog_row_with_xml_unchanged():
    event = winxml.parse_line(LINUX)
    table, row = mapping.to_sentinel(event)
    assert table == "Syslog"
    assert row["SyslogMessage"] == LINUX and row["Computer"] == "host2"
    assert '<Provider Name="Linux-Sysmon"' in row["SyslogMessage"]


def test_read_splits_on_closing_tag_so_embedded_newlines_survive(tmp_path):
    (tmp_path / "x.log").write_text(WINDOWS + "\n" + LINUX + "\n\n", encoding="utf-8")
    events = winxml.read(tmp_path)
    assert len(events) == 2
    assert events[0]["CommandLine"] == "notepad.exe a.txt\nsecond line"


def test_non_event_text_is_skipped():
    assert winxml.parse_line("version https://git-lfs.github.com/spec/v1") is None
