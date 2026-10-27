"""Run rules in a real query engine against recorded open-source attack data.

    python -m harness fetch
    python -m harness run --engine kusto  [--rule A1] [--write]
    python -m harness run --engine splunk [--rule A1] [--write]

For each rule folder that has tests/datasets.yaml, `run` does two passes
in the chosen engine:

1. Samples: load tests/positive.json, run the rule's query, expect every
   positive case to produce a row; then load tests/negative.json alone
   and expect no rows. A case is one event, or the events that share a
   `_case` key: a rule that aggregates (one row per consent, per
   session) needs several events for one row.
2. Datasets: load every event of each dataset listed in
   tests/datasets.yaml (attack and background together), run the query,
   and record each row it returns.

`--write` saves the result to tests/results/<engine>.json in the rule
folder; tests/evidence.md is written from it by hand. Exit code 1 if a
positive did not match, a negative matched, or (without --write) the
dataset match count differs from the committed result.
See docs/components/engine-tests.md.
"""

import argparse
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from collections import Counter
from datetime import date

import yaml

from dac.rules import REPO_ROOT, load_rules

from . import mapping
from .engines import EngineError, KustoEngine, SplunkEngine, data_dir, epoch

DATASETS_FILE = REPO_ROOT / "harness" / "datasets.yaml"
SOURCES = {
    "otrf": "https://raw.githubusercontent.com/OTRF/Security-Datasets/{commit}/{path}",
    # attack_data keeps its logs in Git LFS; raw.githubusercontent.com serves the pointer.
    "splunk-attack-data": "https://media.githubusercontent.com/media/splunk/attack_data/{commit}/{path}",
}
EVENT_FILES = ("*.json", "*.log")
SIEM_FOR_ENGINE = {"kusto": ("sentinel", "query"), "splunk": ("splunk", "search")}
MAX_CELL = 300


def load_catalogue() -> dict:
    return yaml.safe_load(DATASETS_FILE.read_text(encoding="utf-8"))["datasets"]


def fetch(catalogue: dict) -> None:
    for dataset_id, entry in catalogue.items():
        target = data_dir() / dataset_id
        if target.exists() and event_files(target):
            print(f"{dataset_id}: present")
            continue
        url = SOURCES[entry.get("source", "otrf")].format(**entry)
        with urllib.request.urlopen(url, timeout=300) as response:
            blob = response.read()
        digest = hashlib.sha256(blob).hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(f"{dataset_id}: SHA-256 {digest} does not match {entry['sha256']}")
        target.mkdir(parents=True, exist_ok=True)
        if not entry["path"].lower().endswith(".zip"):
            (target / base_name(entry["path"])).write_bytes(blob)
            print(f"{dataset_id}: fetched and verified")
            continue
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for member in archive.infolist():
                # Write by base name only, so no path inside the archive is trusted.
                name = base_name(member.filename)
                if name.endswith(".json") and not name.startswith("."):
                    (target / name).write_bytes(archive.read(member))
        print(f"{dataset_id}: fetched and verified")


def base_name(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def event_files(folder) -> list:
    return sorted(p for pattern in EVENT_FILES for p in folder.glob(pattern))


def read_events(dataset_id: str) -> list[dict]:
    files = event_files(data_dir() / dataset_id)
    if not files:
        raise SystemExit(f"{dataset_id}: not fetched; run `python -m harness fetch`")
    events = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def load_into(engine, events: list[dict]) -> dict:
    """Reset the engine, load events, return what was dropped in mapping."""
    engine.reset()
    if engine.name == "kusto":
        rows: dict[str, list[dict]] = {t: [] for t in engine.tables}
        unmapped = Counter()
        for event in events:
            table, row = mapping.to_sentinel(event)
            if table is None:
                unmapped[event.get("category", "?")] += 1
            else:
                rows[table].append(row)
        dropped = engine.load(rows)
        if unmapped:
            # Log categories with no table loaded here (e.g. ServicePrincipalSignInLogs).
            dropped["events_not_loaded"] = dict(sorted(unmapped.items()))
        return dropped
    engine.load([(mapping.splunk_source(e), e.get("Hostname", ""), mapping.to_windows_xml(e),
                  epoch(mapping.timestamp(e))) for e in events])
    return {}


def trim(row: dict) -> dict:
    return {k: (v[:MAX_CELL] + "...") if isinstance(v, str) and len(v) > MAX_CELL else v
            for k, v in row.items() if not k.startswith("_") or k == "_time"}


def run_rule(engine, rule, catalogue: dict) -> dict:
    siem, key = SIEM_FOR_ENGINE[engine.name]
    query = rule.data[siem][key]
    tests = rule.folder / "tests"
    positives = json.loads((tests / "positive.json").read_text(encoding="utf-8"))
    negatives = json.loads((tests / "negative.json").read_text(encoding="utf-8"))
    dataset_ids = yaml.safe_load((tests / "datasets.yaml").read_text(encoding="utf-8"))["datasets"]

    load_into(engine, positives)
    pos_rows = engine.query(query)
    load_into(engine, negatives)
    neg_rows = engine.query(query)

    events = [e for d in dataset_ids for e in read_events(d)]
    dropped = load_into(engine, events)
    ds_rows = engine.query(query)

    return {
        "rule_id": rule.id,
        "rule_version": rule.version,
        "engine": engine.version(),
        "date": date.today().isoformat(),
        "samples": {
            "positive_events": len(positives),
            "positive_cases": cases(positives),
            "positive_rows": len(pos_rows),
            "negative_events": len(negatives),
            "negative_rows": len(neg_rows),
        },
        "datasets": [{"id": d, "commit": catalogue[d]["commit"], "path": catalogue[d]["path"],
                      "sha256": catalogue[d]["sha256"]} for d in dataset_ids],
        "dataset_events": len(events),
        "dataset_rows": len(ds_rows),
        "matched": [trim(r) for r in ds_rows],
        "columns_dropped_in_mapping": dropped,
    }


def cases(samples: list[dict]) -> int:
    """Positive cases: events grouped by `_case`; an event without one is its own case."""
    return len({e.get("_case", f"event {i}") for i, e in enumerate(samples)})


def check(result: dict, committed: dict | None) -> list[str]:
    problems = []
    s = result["samples"]
    expected = s.get("positive_cases", s["positive_events"])
    if s["positive_rows"] < expected:
        problems.append(f"{expected} positive cases, only {s['positive_rows']} rows")
    if s["negative_rows"]:
        problems.append(f"{s['negative_rows']} rows from negative samples")
    if committed is not None and committed["dataset_rows"] != result["dataset_rows"]:
        problems.append(f"dataset rows {result['dataset_rows']} differ from committed {committed['dataset_rows']}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch")
    run = sub.add_parser("run")
    run.add_argument("--engine", choices=sorted(SIEM_FOR_ENGINE), required=True)
    run.add_argument("--rule", help="folder name prefix, e.g. A1")
    run.add_argument("--write", action="store_true", help="save tests/results/<engine>.json")
    args = parser.parse_args(argv)

    catalogue = load_catalogue()
    if args.command == "fetch":
        fetch(catalogue)
        return 0

    try:
        engine = KustoEngine() if args.engine == "kusto" else SplunkEngine()
    except EngineError as err:
        print(err, file=sys.stderr)
        return 2
    rules = [r for r in load_rules() if (r.folder / "tests" / "datasets.yaml").exists()
             and (not args.rule or r.folder.name.startswith(args.rule))
             and SIEM_FOR_ENGINE[args.engine][0] in r.data]
    if not rules:
        print("no matching rules with tests/datasets.yaml", file=sys.stderr)
        return 2
    failed = False
    for rule in rules:
        result = run_rule(engine, rule, catalogue)
        out = rule.folder / "tests" / "results" / f"{args.engine}.json"
        committed = None if args.write or not out.exists() else json.loads(out.read_text(encoding="utf-8"))
        problems = check(result, committed)
        s = result["samples"]
        print(f"{rule.folder.name} [{args.engine}]: positive rows {s['positive_rows']} for {s['positive_cases']} cases, "
              f"negatives {s['negative_rows']}/{s['negative_events']}, "
              f"datasets {result['dataset_rows']} rows from {result['dataset_events']} events"
              + (f"  FAIL: {'; '.join(problems)}" if problems else "  ok"))
        failed |= bool(problems)
        if args.write:
            out.parent.mkdir(exist_ok=True)
            out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
