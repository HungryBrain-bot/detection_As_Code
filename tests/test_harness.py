"""Offline tests for the engine harness: mapping, result checks, dataset fetch.

The engine runs themselves need the Kusto or Splunk container and are
exercised by `python -m harness run` (CI job `engine-kusto`), not here.
"""

import hashlib
import io
import json
import zipfile
from xml.etree import ElementTree

import pytest

import harness.__main__ as hmain
from harness import mapping

SECURITY_4688 = {
    "@timestamp": "2020-09-04T20:09:57.091Z", "Channel": "security", "EventID": 4688,
    "SourceName": "Microsoft-Windows-Security-Auditing", "Hostname": "WS5", "EventType": "AUDIT_SUCCESS",
    "SubjectUserName": "pgustavo", "SubjectDomainName": "THESHIRE", "Message": "A new process has been created.\r\n...",
    "NewProcessName": "C:\\Windows\\System32\\reg.exe", "CommandLine": 'reg save HKLM\\sam sam & "x" <y>',
    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "RecordNumber": 7,
}
SYSMON_13 = {
    "@timestamp": "2020-07-22T04:19:05.132Z", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13,
    "SourceName": "Microsoft-Windows-Sysmon", "Hostname": "WS5", "Domain": "NT AUTHORITY", "AccountName": "SYSTEM",
    "EventType": "SetValue", "Image": "C:\\x.exe", "TargetObject": "HKLM\\Software\\Run\\a", "Details": "a & b",
    "Version": 2, "Task": 13,
}


def test_security_event_row():
    table, row = mapping.to_sentinel(SECURITY_4688)
    assert table == "SecurityEvent"
    assert row["Account"] == "THESHIRE\\pgustavo"
    assert row["Channel"] == "Security"            # lower-case channel normalised
    assert row["EventID"] == 4688 and row["Computer"] == "WS5"
    assert row["CommandLine"] == SECURITY_4688["CommandLine"]  # values copied unchanged
    assert "EventType" not in row                   # NXLog audit result is not EventData
    assert "Message" not in row and "RecordNumber" not in row


def test_sysmon_event_xml_is_what_the_microsoft_parser_reads():
    table, row = mapping.to_sentinel(SYSMON_13)
    assert table == "Event" and row["Source"] == "Microsoft-Windows-Sysmon"
    assert row["UserName"] == "NT AUTHORITY\\SYSTEM"
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    data = ElementTree.fromstring(row["EventData"]).find(f"{ns}EventData")
    fields = {d.get("Name"): d.text for d in data}
    assert fields == {"EventType": "SetValue", "Image": "C:\\x.exe",
                      "TargetObject": "HKLM\\Software\\Run\\a", "Details": "a & b"}


def test_windows_xml_round_trips_values():
    root = ElementTree.fromstring(mapping.to_windows_xml(SECURITY_4688))
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    assert root.find(f"{ns}System/{ns}EventID").text == "4688"
    fields = {d.get("Name"): d.text for d in root.find(f"{ns}EventData")}
    assert fields["CommandLine"] == SECURITY_4688["CommandLine"]
    assert mapping.splunk_source(SECURITY_4688) == "XmlWinEventLog:Security"


def test_timecreated_is_read_as_utc():
    assert mapping.timestamp({"TimeCreated": "2020-10-19 12:28:31.089"}) == "2020-10-19T12:28:31.089Z"


def test_samples_metadata_is_not_event_data():
    event = dict(SECURITY_4688, _provenance="hand-written", _note="x")
    _, row = mapping.to_sentinel(event)
    assert "_provenance" not in row and "_note" not in row


@pytest.mark.parametrize("samples, committed, problems", [
    ({"positive_events": 2, "positive_rows": 2, "negative_events": 3, "negative_rows": 0}, None, 0),
    ({"positive_events": 2, "positive_rows": 1, "negative_events": 3, "negative_rows": 0}, None, 1),
    ({"positive_events": 2, "positive_rows": 2, "negative_events": 3, "negative_rows": 1}, None, 1),
    ({"positive_events": 2, "positive_rows": 2, "negative_events": 3, "negative_rows": 0}, {"dataset_rows": 5}, 1),
])
def test_check(samples, committed, problems):
    result = {"samples": samples, "dataset_rows": 2}
    assert len(hmain.check(result, committed)) == problems


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


def _serve(monkeypatch, blob: bytes):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False
    monkeypatch.setattr(hmain.urllib.request, "urlopen", lambda url, timeout: Response(blob))


def test_fetch_verifies_hash_and_writes_by_base_name(tmp_path, monkeypatch):
    blob = _zip({"../../evil.json": b"{}", "dir/events.json": b'{"EventID": 1}\n', "readme.txt": b"x"})
    _serve(monkeypatch, blob)
    monkeypatch.setattr(hmain, "data_dir", lambda: tmp_path)
    hmain.fetch({"d": {"commit": "c", "path": "p.zip", "sha256": hashlib.sha256(blob).hexdigest()}})
    assert sorted(p.name for p in (tmp_path / "d").iterdir()) == ["events.json", "evil.json"]
    assert not (tmp_path.parent / "evil.json").exists()
    assert json.loads((tmp_path / "d" / "events.json").read_text()) == {"EventID": 1}


def test_fetch_rejects_wrong_hash(tmp_path, monkeypatch):
    _serve(monkeypatch, _zip({"a.json": b"{}"}))
    monkeypatch.setattr(hmain, "data_dir", lambda: tmp_path)
    with pytest.raises(SystemExit):
        hmain.fetch({"d": {"commit": "c", "path": "p.zip", "sha256": "0" * 64}})
    assert not (tmp_path / "d").exists()
