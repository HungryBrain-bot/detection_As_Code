"""Local query engines the harness runs rules in.

KustoEngine: the Azure Data Explorer emulator ("Kustainer",
mcr.microsoft.com/azuredataexplorer/kustainer-linux). It is the ADX
engine, not Log Analytics: Sentinel runs on Log Analytics, which shares
the KQL language but not every function. A rule that uses a
Log-Analytics-only function fails here, which is visible, not silent.

SplunkEngine: a Splunk Enterprise container (splunk/splunk). Splunk's
Windows add-on (Splunk_TA_windows) is not installed, because it needs a
Splunkbase login; instead `setup()` installs a minimal search-time
extraction for XmlWinEventLog: every <Data Name='X'>v</Data> becomes
field X, and <EventID> becomes EventCode. That approximates the add-on's
field names for these events; it does not reproduce its CIM aliases or
any other extraction.

Both talk plain HTTP(S) with the standard library. Connection settings
come from environment variables (see docs/components/engine-tests.md);
the passwords and tokens are for a local test container only.
"""

import base64
import json
import os
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from dac.rules import load_reference_schema

# Column types where the vendor page gives them; everything else is string.
TYPED_COLUMNS = {
    "TimeGenerated": "datetime", "EventID": "int", "EventLevel": "int",
    "EventCategory": "int", "_BilledSize": "real",
}
INGEST_CHUNK = 2000


class EngineError(RuntimeError):
    pass


def _post(url: str, body: bytes, headers: dict, context=None, timeout=120) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.read()
    except urllib.error.HTTPError as err:
        raise EngineError(f"{url} -> HTTP {err.code}: {err.read()[:500]!r}") from err


class KustoEngine:
    name = "kusto"
    tables = ("SecurityEvent", "Event")

    def __init__(self, url: str | None = None, database: str = "NetDefaultDB"):
        self.url = (url or os.environ.get("DAC_KUSTO_URL", "http://localhost:8080")).rstrip("/")
        self.database = database
        self.columns: dict[str, list[str]] = {}

    def _call(self, path: str, csl: str) -> dict | list:
        body = json.dumps({"db": self.database, "csl": csl}).encode()
        raw = _post(self.url + path, body, {"Content-Type": "application/json"})
        return json.loads(raw)

    def mgmt(self, csl: str):
        return self._call("/v1/rest/mgmt", csl)

    def reset(self):
        """Drop and recreate the tables from their reference schemas."""
        for table in self.tables:
            schema = load_reference_schema("sentinel", table)
            if schema is None:
                raise EngineError(f"no reference schema for {table}")
            fields = schema["fields"]
            self.columns[table] = fields
            cols = ", ".join(f"['{f}']:{TYPED_COLUMNS.get(f, 'string')}" for f in fields)
            self.mgmt(f".drop table ['{table}'] ifexists")
            self.mgmt(f".create table ['{table}'] ({cols})")

    def load(self, rows_by_table: dict[str, list[dict]]) -> dict[str, list[str]]:
        """Ingest rows; returns, per table, the row keys that are not columns (dropped)."""
        dropped = {}
        for table, rows in rows_by_table.items():
            known = set(self.columns[table])
            extra = sorted({k for row in rows for k in row} - known)
            if extra:
                dropped[table] = extra
            for start in range(0, len(rows), INGEST_CHUNK):
                chunk = rows[start:start + INGEST_CHUNK]
                lines = "\n".join(json.dumps({k: v for k, v in r.items() if k in known}) for r in chunk)
                self.mgmt(f".ingest inline into table ['{table}'] with (format='multijson') <|\n{lines}")
        return dropped

    def count(self, table: str) -> int:
        return self.query(f"['{table}'] | count")[0]["Count"]

    def query(self, kql: str) -> list[dict]:
        frames = self._call("/v2/rest/query", kql)
        for frame in frames:
            if frame.get("FrameType") == "DataTable" and frame.get("TableKind") == "PrimaryResult":
                names = [c["ColumnName"] for c in frame["Columns"]]
                return [dict(zip(names, row)) for row in frame["Rows"]]
            if frame.get("FrameType") == "DataSetCompletion" and frame.get("HasErrors"):
                raise EngineError(json.dumps(frame.get("OneApiErrors"))[:1000])
        return []

    def version(self) -> str:
        rows = self.mgmt(".show version")["Tables"][0]["Rows"]
        return f"Kustainer (ADX engine) {rows[0][0]}, product {rows[0][3]}"


class SplunkEngine:
    name = "splunk"
    index = "wineventlog"
    sourcetype = "XmlWinEventLog"

    def __init__(self):
        env = os.environ
        self.url = env.get("DAC_SPLUNK_URL", "https://localhost:8089").rstrip("/")
        self.hec_url = env.get("DAC_SPLUNK_HEC_URL", "https://localhost:8088").rstrip("/")
        self.hec_token = env.get("DAC_SPLUNK_HEC_TOKEN", "")
        user, password = env.get("DAC_SPLUNK_USER", "admin"), env.get("DAC_SPLUNK_PASSWORD", "")
        if not password or not self.hec_token:
            raise EngineError("set DAC_SPLUNK_PASSWORD and DAC_SPLUNK_HEC_TOKEN for the local Splunk container")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        # The container's management and HEC ports use a self-signed certificate.
        # Only skip verification for a local container, and only when asked to.
        self.context = None
        if env.get("DAC_SPLUNK_INSECURE") == "1":
            host = urllib.parse.urlparse(self.url).hostname
            if host not in ("localhost", "127.0.0.1"):
                raise EngineError("DAC_SPLUNK_INSECURE is only allowed for a localhost container")
            self.context = ssl._create_unverified_context()

    def _rest(self, path: str, params: dict | None = None) -> bytes:
        params = dict(params or {}, output_mode="json")
        return _post(self.url + path, urllib.parse.urlencode(params, doseq=True).encode(),
                     {"Authorization": self.auth}, self.context, timeout=600)

    def setup(self):
        """Index, delete permission and the XmlWinEventLog extraction (idempotent)."""
        for path, params in [
            ("/services/data/indexes", {"name": self.index}),
            ("/servicesNS/nobody/search/configs/conf-transforms",
             {"name": "dac_xml_data", "REGEX": "<Data Name='([^']+)'>([^<]*)</Data>",
              "FORMAT": "$1::$2", "MV_ADD": "true"}),
            ("/servicesNS/nobody/search/configs/conf-transforms",
             {"name": "dac_xml_eventcode", "REGEX": "<EventID[^>]*>(\\d+)</EventID>", "FORMAT": "EventCode::$1"}),
            ("/servicesNS/nobody/search/configs/conf-props",
             {"name": self.sourcetype, "KV_MODE": "none",
              "REPORT-dac": "dac_xml_data, dac_xml_eventcode"}),
        ]:
            try:
                self._rest(path, params)
            except EngineError as err:
                if "409" not in str(err) and "already exists" not in str(err):
                    raise
        self._rest("/services/authentication/users/admin", {"roles": ["admin", "can_delete"]})

    def reset(self):
        self.setup()
        self.search(f"search index={self.index} | delete")

    def load(self, events: list[tuple[str, str, str, float]]) -> None:
        """events: (source, host, xml, epoch time)."""
        url = self.hec_url + "/services/collector/event"
        headers = {"Authorization": f"Splunk {self.hec_token}"}
        for start in range(0, len(events), INGEST_CHUNK):
            body = "\n".join(json.dumps({
                "time": t, "host": host, "source": source, "sourcetype": self.sourcetype,
                "index": self.index, "event": xml,
            }) for source, host, xml, t in events[start:start + INGEST_CHUNK]).encode()
            _post(url, body, headers, self.context)
        deadline = time.time() + 300
        while time.time() < deadline:
            if self.count() >= len(events):
                return
            time.sleep(3)
        raise EngineError(f"only {self.count()} of {len(events)} events indexed after 300s")

    def count(self) -> int:
        # A search, not tstats: events removed with `| delete` must not count.
        rows = self.search(f"search index={self.index} | stats count")
        return int(rows[0]["count"]) if rows else 0

    def search(self, spl: str) -> list[dict]:
        spl = spl.strip()
        if not spl.startswith("|") and not spl.startswith("search "):
            spl = "search " + spl
        raw = self._rest("/services/search/jobs/export",
                         {"search": spl, "earliest_time": "0", "latest_time": "now"})
        rows = []
        for line in raw.decode().splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("messages"):
                for msg in item["messages"]:
                    if msg.get("type") in ("FATAL", "ERROR"):
                        raise EngineError(msg.get("text"))
            if "result" in item:
                rows.append(item["result"])
        return rows

    query = search

    def version(self) -> str:
        request = urllib.request.Request(self.url + "/services/server/info?output_mode=json",
                                         headers={"Authorization": self.auth})
        with urllib.request.urlopen(request, context=self.context, timeout=60) as response:
            content = json.loads(response.read())["entry"][0]["content"]
        return f"Splunk Enterprise {content['version']} (build {content['build']}), XmlWinEventLog extraction from harness/engines.py"


def epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def data_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "datasets"
