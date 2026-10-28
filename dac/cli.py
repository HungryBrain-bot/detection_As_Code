"""Command line: python -m dac <command>.

    validate [--attack-bundle F] [--atlas-data F]  offline checks on every rule and customer
    customers [--json]                         list customer/SIEM pairs (CI matrix)
    schema-check --customer C --siem S         compare rules' required fields with the SIEM
    gate --customer C --siem S [--report-only] log-source gate; sends reminders
    plan --siem S [--customer C]               write the deploy requests to build/
    deploy --customer C --siem S [--mode M]    gate, then deploy the allowed rules
                                               M = dry-run (default) | live | auto
                                               auto = live if every credential env
                                               var is set, else dry-run
    coverage --customer C [--attack-bundle F]  Navigator layers + summary for the customer
    llm-inventory --customer C                 which LLM rules each of the customer's LLM apps
                                               can feed (docs/components/llm-telemetry.md)

Probes run whenever the adapter's read-only credentials are set; without
them, schema-check and the gate use customer schema files and human
confirmations only.

Exit codes: 0 ok, 1 validation or deploy error, 2 blocked by the gate
(llm-inventory: an app cannot feed a rule),
3 --mode live without credentials, 4 unknown customer.
"""

import argparse
import json
import sys
from pathlib import Path

from .adapters import get_adapter
from .coverage import write_coverage
from .gate import run_gate
from .llm_inventory import load_inventory, report as llm_report, validate_inventory
from .rules import (CUSTOMERS_DIR, DETECTIONS_DIR, REPO_ROOT, SIEMS, load_customer, load_customers,
                    load_log_sources, load_rules)
from .schema_check import OK, check_rule
from .validate import (attack_bundle_version, load_atlas_index, load_attack_index, validate_all,
                       validate_customers)

BUILD_DIR = REPO_ROOT / "build"
REPORTS_DIR = REPO_ROOT / "reports"


def _customer(args):
    folder = args.customers_dir / args.customer
    if not (folder / "customer.yaml").exists():
        print(f"unknown customer {args.customer!r} (no {folder}/customer.yaml)")
        return None
    return load_customer(folder)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def cmd_validate(args) -> int:
    rules = load_rules(args.rules_dir)
    catalogue = load_log_sources()
    attack_index = load_attack_index(args.attack_bundle) if args.attack_bundle else None
    if attack_index is None:
        print("note: no --attack-bundle given, ATT&CK IDs not checked against MITRE data")
    atlas_index = load_atlas_index(args.atlas_data) if args.atlas_data else None
    if atlas_index is None:
        print("note: no --atlas-data given, ATLAS IDs not checked against MITRE ATLAS data")
    results = validate_all(rules, catalogue, attack_index, atlas_index)
    inventory_errors = validate_inventory(load_inventory(), catalogue)
    if inventory_errors:
        results["llm_log_inventory.yaml"] = inventory_errors
    results.update({f"customer {k}": v for k, v in
                    validate_customers(load_customers(args.customers_dir), rules, catalogue).items()})
    for where, errors in results.items():
        print(f"FAIL {where}")
        for error in errors:
            print(f"  - {error}")
    print(f"{len(rules)} rule(s), {len(results)} item(s) with errors")
    return 1 if results else 0


def cmd_customers(args) -> int:
    pairs = [{"customer": c.id, "siem": s} for c in load_customers(args.customers_dir)
             for s in c.siems if s in SIEMS]
    print(json.dumps(pairs) if args.json else "\n".join(f"{p['customer']} {p['siem']}" for p in pairs))
    return 0


def cmd_schema_check(args) -> int:
    customer = _customer(args)
    if customer is None:
        return 4
    adapter = get_adapter(args.siem)
    mode = "live probe" if adapter.has_probe_credentials() else "customer schema files only (no probe credentials)"
    lines = [f"# Schema check: {customer.name}, {args.siem}", "", f"Basis: {mode}.", ""]
    problems = 0
    cache = {}
    for rule in customer.applicable_rules(load_rules(args.rules_dir)):
        if args.siem not in rule.targets():
            continue
        lines.append(f"## {rule.name}")
        for check in check_rule(rule, args.siem, customer, adapter, cache):
            lines.append(f"- {check.describe()}")
            problems += check.status != OK
        lines.append("")
    report = "\n".join(lines)
    print(report)
    out = REPORTS_DIR / "schema" / customer.id / f"{args.siem}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report + "\n", encoding="utf-8")
    print(f"written {_rel(out)}")
    return 0 if problems == 0 else 2


def _gate(args, customer, notify=True):
    rules = load_rules(args.rules_dir)
    result = run_gate(rules, args.siem, load_log_sources(), customer,
                      adapter=get_adapter(args.siem), notify=notify)
    for rule_id in result.allowed:
        how = " (auto-confirmed by probe)" if rule_id in result.auto_confirmed else ""
        print(f"ALLOW {rule_id}{how}")
    for rule_id, reasons in result.blocked.items():
        print(f"BLOCK {rule_id}: {'; '.join(reasons)}")
    for delivery in result.deliveries:
        print(f"reminder sent: {delivery}")
    return rules, result


def cmd_gate(args) -> int:
    customer = _customer(args)
    if customer is None:
        return 4
    _, result = _gate(args, customer)
    if result.passed or args.report_only:
        return 0
    return 2


def _write_plan(siem: str, rules, rule_ids: list[str], label: str) -> list[Path]:
    adapter = get_adapter(siem)
    out_dir = BUILD_DIR / label / siem
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for rule in rules:
        if rule.id not in rule_ids:
            continue
        path = out_dir / f"{rule.id}.json"
        path.write_text(json.dumps(adapter.build_request(rule).redacted(), indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


def cmd_plan(args) -> int:
    rules = load_rules(args.rules_dir)
    label = "all"
    if args.customer:
        customer = _customer(args)
        if customer is None:
            return 4
        rules, label = customer.applicable_rules(rules), customer.id
    rules = [r for r in rules if args.siem in r.targets()]
    for path in _write_plan(args.siem, rules, [r.id for r in rules], label):
        print(f"planned {_rel(path)}")
    return 0


def cmd_deploy(args) -> int:
    customer = _customer(args)
    if customer is None:
        return 4
    rules, result = _gate(args, customer)
    adapter = get_adapter(args.siem)
    live = args.mode == "live" or (args.mode == "auto" and adapter.has_credentials())
    if args.mode == "live" and not adapter.has_credentials():
        print(f"--mode live: missing env vars for {args.siem}: {', '.join(adapter.missing_credentials())}")
        return 3
    if args.mode == "auto" and not live:
        print(f"auto: no credentials for {args.siem} "
              f"({', '.join(adapter.missing_credentials())}), dry-run only")
    if not live:
        for path in _write_plan(args.siem, rules, result.allowed, customer.id):
            print(f"dry-run: would send {_rel(path)}")
    else:
        failed = False
        for rule in rules:
            if rule.id in result.allowed:
                try:
                    adapter.deploy(rule)
                    print(f"deployed {rule.id}")
                except Exception as exc:  # report every rule, then fail
                    failed = True
                    print(f"FAILED {rule.id}: {exc}")
        if failed:
            return 1
    return 0 if result.passed or args.report_only else 2


def cmd_coverage(args) -> int:
    customer = _customer(args)
    if customer is None:
        return 4
    rules = load_rules(args.rules_dir)
    catalogue = load_log_sources()
    results = [run_gate(rules, siem, catalogue, customer, adapter=get_adapter(siem), notify=False)
               for siem in customer.siems]
    version = attack_bundle_version(args.attack_bundle) if args.attack_bundle else None
    for path in write_coverage(customer, rules, results, out_dir=REPORTS_DIR / "coverage",
                               attack_version=version):
        print(f"written {_rel(path)}")
    return 0


def cmd_llm_inventory(args) -> int:
    customer = _customer(args)
    if customer is None:
        return 4
    text, gaps = llm_report(customer, load_rules(args.rules_dir), load_inventory(), load_log_sources())
    print(text)
    out = REPORTS_DIR / "llm" / f"{customer.id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"written {_rel(out)}")
    return 0 if gaps == 0 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m dac")
    parser.add_argument("--rules-dir", type=Path, default=DETECTIONS_DIR)
    parser.add_argument("--customers-dir", type=Path, default=CUSTOMERS_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate")
    p.add_argument("--attack-bundle", type=Path)
    p.add_argument("--atlas-data", type=Path, help="atlas-data dist/v6 YAML, e.g. ATLAS-2026.06.yaml")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("customers")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_customers)

    for name, func in (("schema-check", cmd_schema_check), ("gate", cmd_gate),
                       ("plan", cmd_plan), ("deploy", cmd_deploy)):
        p = sub.add_parser(name)
        p.add_argument("--siem", required=True, choices=list(SIEMS))
        p.add_argument("--customer", required=name != "plan")
        if name in ("gate", "deploy"):
            p.add_argument("--report-only", action="store_true",
                           help="blocked rules are reported and reminded, but do not fail the exit code")
        if name == "deploy":
            p.add_argument("--mode", choices=["dry-run", "live", "auto"], default="dry-run")
        p.set_defaults(func=func)

    p = sub.add_parser("coverage")
    p.add_argument("--customer", required=True)
    p.add_argument("--attack-bundle", type=Path)
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("llm-inventory")
    p.add_argument("--customer", required=True)
    p.set_defaults(func=cmd_llm_inventory)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
