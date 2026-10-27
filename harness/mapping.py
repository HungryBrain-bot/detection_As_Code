"""Turn a recorded OTRF event back into the shape each SIEM stores it in.

OTRF Security-Datasets events were collected with NXLog (im_msvistalog)
and flattened to one JSON object per event: the Windows EventData fields
as top-level keys, plus NXLog's own metadata keys. No SIEM stores them
like that, so before a rule's query can run, each event is rebuilt:

- Sentinel `SecurityEvent` (Security channel): the EventData fields
  become columns of the same name, which is how the SecurityEvent table
  names them (CommandLine, NewProcessName, ParentProcessName, ...).
  Computer, Account, Activity and EventSourceName are filled from the
  NXLog metadata.
- Sentinel `Event` (Sysmon channel): EventData is rebuilt as XML in the
  shape Microsoft's own Sysmon parser reads
  (`parse_xml(EventData).DataItem.EventData.Data`, each element with
  `@Name` and `#text`; Azure-Sentinel Parsers/Sysmon/Sysmon-AllVersions_Parser.txt).
- Splunk `XmlWinEventLog`: the event is rebuilt as Windows event XML
  (<Event><System>...</System><EventData><Data Name='...'>...</Data></EventData></Event>).

What is approximated, and so not evidence of anything:
- The DataItem wrapper attributes in Event.EventData and the System
  block in the Splunk XML are written by this module, not recorded.
  The rules do not read them.
- SecurityEvent column types: only TimeGenerated (datetime) and
  EventID (int) are typed; every other column is a string.
- Newer OTRF files carry "TimeCreated" ("2020-10-19 12:28:31.089")
  instead of "@timestamp"; it is read as UTC.
- The standard-user dataset records the Security channel as
  "security"; it is normalised to "Security".

Field values (command lines, paths, registry keys) are copied unchanged,
including NXLog's own escaping (e.g. "&gt;" in a command line).

Entra ID logs (identity rules) come in two shapes:

- Azure Monitor diagnostic format (Splunk attack_data, sourcetype
  azure:monitor:aad): one JSON object per record with `time`,
  `category`, `operationName`, ... at the top and the log entry itself
  under `properties` in camelCase. `category` picks the table
  (AuditLogs -> AuditLogs, SignInLogs -> SigninLogs,
  NonInteractiveUserSignInLogs -> AADNonInteractiveUserSignInLogs);
  other categories (service principal sign-ins, Graph activity) have no
  table here and are not loaded, and the result file counts them.
  Each key becomes the table column with the same name ignoring case
  (ipAddress -> IPAddress), after the renames in ENTRA_RENAMES, which
  are the columns whose names differ from the diagnostic key. Keys with
  no column are dropped on load and listed in the result file.
- A Sentinel export (OTRF): rows already named as the table's columns,
  plus columns derived by the exporting query (keyEvents, target, ...),
  which have no column and are dropped on load. Dynamic columns were
  exported as JSON text; the engine parses them back. A row is
  recognised by its AuditLogs columns, not by `Type`: on two of the four
  rows the export's Type holds the target type ("Application",
  "ServicePrincipal"), overwritten by a derived column, and is reset to
  "AuditLogs". The export repeats one row (same Id); it is loaded twice,
  as recorded.

What is approximated for Entra:
- Column types follow the reference schema (`types`); the engine turns
  a nested value into JSON text for a string column (as
  AADNonInteractiveUserSignInLogs stores LocationDetails, Status and
  others) and parses JSON text for a dynamic column.
- Properties present in both places take the `properties` value
  (AuditLogs Category is "ApplicationManagement", not "AuditLogs").
"""

from functools import cache
from xml.sax.saxutils import escape, quoteattr

from dac.rules import load_reference_schema

# NXLog / Logstash metadata keys: not part of the Windows EventData.
NXLOG_META = {
    "@timestamp", "@version", "tags", "host", "port", "Hostname", "Keywords",
    "EventTime", "EventReceivedTime", "SeverityValue", "Severity", "SourceName",
    "ProviderGuid", "Version", "Task", "OpcodeValue", "Opcode", "RecordNumber",
    "ExecutionProcessID", "ThreadID", "Channel", "Domain", "AccountName",
    "UserID", "AccountType", "Category", "Message", "SourceModuleName",
    "SourceModuleType", "EventTypeOrignal", "EventID", "ERROR_EVT_UNRESOLVED",
    "ActivityID", "EventIdx", "EventCountTotal", "TimeCreated",
}

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def channel(event: dict) -> str:
    value = event.get("Channel") or ""
    return "Security" if value.lower() == "security" else value


def timestamp(event: dict) -> str:
    """ISO 8601 UTC time of the event."""
    if event.get("@timestamp"):
        return event["@timestamp"]
    return event["TimeCreated"].replace(" ", "T") + "Z"


def event_data(event: dict) -> dict[str, str]:
    """The Windows EventData fields of a flattened event, as strings."""
    data = {}
    for key, value in event.items():
        if key in NXLOG_META or key.startswith("_"):
            continue
        # On the Security channel NXLog's EventType is the audit result, not EventData.
        if key == "EventType" and channel(event) != SYSMON_CHANNEL:
            continue
        data[key] = "" if value is None else str(value)
    return data


def _user(event: dict) -> str:
    if event.get("Domain") and event.get("AccountName"):
        return f"{event['Domain']}\\{event['AccountName']}"
    return event.get("AccountName") or ""


def to_security_event(event: dict) -> dict:
    """Security channel event -> Sentinel SecurityEvent row."""
    data = event_data(event)
    row = dict(data)
    subject = data.get("SubjectUserName")
    account = f"{data.get('SubjectDomainName', '')}\\{subject}" if subject else ""
    lines = (event.get("Message") or "").splitlines()
    row.update({
        "TimeGenerated": timestamp(event),
        "EventID": int(event["EventID"]),
        "Computer": event.get("Hostname", ""),
        "Channel": "Security",
        "EventSourceName": event.get("SourceName", ""),
        "Activity": f"{event['EventID']} - {lines[0]}" if lines else str(event["EventID"]),
        "Account": account,
        "Type": "SecurityEvent",
    })
    return row


def to_event(event: dict) -> dict:
    """Non-Security event (Sysmon, PowerShell, System) -> Sentinel Event row."""
    data = event_data(event)
    items = "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items())
    xml = ("<DataItem type=\"System.XmlData\">"
           "<EventData xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
           f"{items}</EventData></DataItem>")
    source = event.get("SourceName", "")
    return {
        "TimeGenerated": timestamp(event),
        "Source": source,
        "EventLog": channel(event),
        "Computer": event.get("Hostname", ""),
        "EventID": int(event["EventID"]),
        "EventLevel": 4,
        "EventLevelName": "Information",
        "UserName": _user(event),
        "RenderedDescription": event.get("Message") or "",
        "EventData": xml,
        "Type": "Event",
    }


ENTRA_TABLES = {
    "AuditLogs": "AuditLogs",
    "SignInLogs": "SigninLogs",
    "NonInteractiveUserSignInLogs": "AADNonInteractiveUserSignInLogs",
}
# Diagnostic keys whose column has a different name, per table ("*" = any).
ENTRA_RENAMES = {
    "*": {"time": "TimeGenerated"},
    "AuditLogs": {"operationType": "AADOperationType", "tenantId": "AADTenantId"},
    "SigninLogs": {"location": "LocationDetails", "resourceId": "ResourceIdentity"},
    "AADNonInteractiveUserSignInLogs": {"location": "LocationDetails", "resourceId": "ResourceIdentity"},
}


@cache
def _columns(table: str) -> dict[str, str]:
    """Lower-case name -> column name, from the reference schema."""
    return {f.lower(): f for f in load_reference_schema("sentinel", table)["fields"]}


def _entra_columns(table: str, record: dict, renames: dict) -> dict:
    columns = _columns(table)
    row = {}
    for key, value in record.items():
        name = renames.get(key) or columns.get(key.lower(), key)
        row[name] = value
    return row


def from_azure_monitor(record: dict) -> tuple[str | None, dict]:
    """Azure Monitor diagnostic record (Entra ID) -> (table, row), or (None, {})."""
    table = ENTRA_TABLES.get(record.get("category"))
    if table is None:
        return None, {}
    renames = dict(ENTRA_RENAMES["*"], **ENTRA_RENAMES.get(table, {}))
    top = {k: v for k, v in record.items() if k != "properties" and not k.startswith("_")}
    row = _entra_columns(table, top, {**renames, "location": "Location", "resourceId": "ResourceId"})
    if table == "AuditLogs":
        row["TenantId"] = record.get("tenantId")
    row.update(_entra_columns(table, record.get("properties") or {}, renames))
    row["Type"] = table
    return table, row


# Tables whose rows are written in table shape already (ADR 008): the LLM
# dataset converters (harness/llm_datasets.py) and hand-written samples.
NATIVE_TABLES = ("LLMAppLog_CL", "LLMCanary_CL")


def to_sentinel(event: dict) -> tuple[str | None, dict]:
    """(table, row) for one event; table None if no table here holds it."""
    if event.get("Type") in NATIVE_TABLES:
        return event["Type"], {k: v for k, v in event.items() if not k.startswith("_")}
    if "properties" in event and "category" in event:
        return from_azure_monitor(event)
    if "ActivityDisplayName" in event and "AADOperationType" in event:
        row = {k: v for k, v in event.items() if not k.startswith("_")}
        return "AuditLogs", dict(row, Type="AuditLogs")
    if channel(event) == "Security":
        return "SecurityEvent", to_security_event(event)
    return "Event", to_event(event)


def to_windows_xml(event: dict) -> str:
    """Event -> Windows event XML as Splunk's XmlWinEventLog stores it (one line)."""
    data = event_data(event)
    items = "".join(f"<Data Name='{escape(k, {chr(39): '&apos;'})}'>{escape(v)}</Data>" for k, v in data.items())
    system = (
        f"<System><Provider Name='{escape(event.get('SourceName', ''))}'/>"
        f"<EventID>{int(event['EventID'])}</EventID>"
        f"<TimeCreated SystemTime='{timestamp(event)}'/>"
        f"<EventRecordID>{event.get('RecordNumber', '')}</EventRecordID>"
        f"<Channel>{escape(channel(event))}</Channel>"
        f"<Computer>{escape(event.get('Hostname', ''))}</Computer></System>"
    )
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"{system}<EventData>{items}</EventData></Event>")


def splunk_source(event: dict) -> str:
    return f"XmlWinEventLog:{channel(event)}"
