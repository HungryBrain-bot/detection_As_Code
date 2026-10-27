"""Command line: python -m dac <validate|gate|plan|deploy>.

    validate [--attack-bundle FILE]   offline checks on every rule
    gate --siem S [--report-only]     log-source gate; sends reminders
    plan --siem S                     write the deploy requests to build/<siem>/
    deploy --siem S [--mode M]        gate, then deploy the allowed rules
                                      M = dry-run (default) | live | auto
                                      auto = live if every credential env
                                      var is set, else dry-run

Exit codes: 0 ok, 1 validation or deploy error, 2 blocked by the gate,
3 --mode live without credentials.
"""

import argparse
import json
import sys
from pathlib import Path

from .adapters import get_adapter
from .gate import run_gate
from .rules import DETECTIONS_DIR, REPO_ROOT, load_log_sources, load_rules, load_teams
from .validate import load_attack_index, validate_all

BUILD_DIR = REPO_ROOT / "build"


def cmd_validate(args) -> int:
    rules = load_rules(args.rules_dir)
    attack_index = load_attack_index(args.attack_bundle) if args.attack_bundle else None
    if attack_index is None:
        print("note: no --attack-bundle given, ATT&CK IDs not checked against MITRE data")
    results = validate_all(rules, load_log_sources(), attack_index)
    for folder, errors in results.items():
        print(f"FAIL {folder}")
        for error in errors:
            print(f"  - {error}")
    print(f"{len(rules)} rule(s), {len(results)} with errors")
    return 1 if results else 0


def _gate(args):
    rules = load_rules(args.rules_dir)
    result = run_gate(rules, args.siem, load_log_sources(), load_teams())
    for rule_id in result.allowed:
        print(f"ALLOW {rule_id}")
    for rule_id, reasons in result.blocked.items():
        print(f"BLOCK {rule_id}: {'; '.join(reasons)}")
    for delivery in result.deliveries:
        print(f"reminder sent: {delivery}")
    return rules, result


def cmd_gate(args) -> int:
    _, result = _gate(args)
    if result.passed or args.report_only:
        return 0
    return 2


def _write_plan(siem: str, rules, rule_ids: list[str]) -> list[Path]:
    adapter = get_adapter(siem)
    out_dir = BUILD_DIR / siem
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
    rules = [r for r in load_rules(args.rules_dir) if args.siem in r.targets()]
    for path in _write_plan(args.siem, rules, [r.id for r in rules]):
        print(f"planned {path.relative_to(REPO_ROOT)}")
    return 0


def cmd_deploy(args) -> int:
    rules, result = _gate(args)
    adapter = get_adapter(args.siem)
    live = args.mode == "live" or (args.mode == "auto" and adapter.has_credentials())
    if args.mode == "live" and not adapter.has_credentials():
        print(f"--mode live: missing env vars for {args.siem}: {', '.join(adapter.missing_credentials())}")
        return 3
    if args.mode == "auto" and not live:
        print(f"auto: no credentials for {args.siem} "
              f"({', '.join(adapter.missing_credentials())}), dry-run only")
    if not live:
        for path in _write_plan(args.siem, rules, result.allowed):
            print(f"dry-run: would send {path.relative_to(REPO_ROOT)}")
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
    return 0 if result.passed else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m dac")
    parser.add_argument("--rules-dir", type=Path, default=DETECTIONS_DIR)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate")
    p.add_argument("--attack-bundle", type=Path)
    p.set_defaults(func=cmd_validate)

    for name, func in (("gate", cmd_gate), ("plan", cmd_plan), ("deploy", cmd_deploy)):
        p = sub.add_parser(name)
        p.add_argument("--siem", required=True, choices=["sentinel", "splunk", "secops"])
        if name == "gate":
            p.add_argument("--report-only", action="store_true", help="send reminders but exit 0")
        if name == "deploy":
            p.add_argument("--mode", choices=["dry-run", "live", "auto"], default="dry-run")
        p.set_defaults(func=func)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
