"""Command-line interface: ``python -m loganalyzer <command>``."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .engine import AnalysisResult, analyze
from .evaluate import evaluate, format_evaluation
from .models import SEVERITY_ORDER, Event, ParseStats
from .parsers import parse_auth_log, parse_web_access, parse_windows_events
from .report import build_report, render_markdown, write_json
from .rules import DEFAULT_RULES_PATH, RuleError, load_rules
from . import synthetic

EXIT_OK, EXIT_ALERTS, EXIT_USAGE = 0, 2, 3
SEV_COLOUR = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}


def _read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def load_events(auth: Sequence[str], windows: Sequence[str], web: Sequence[str], year: Optional[int],
                web_host: Optional[str] = None):
    events: List[Event] = []
    stats: List[ParseStats] = []
    for path in auth:
        ev, st = parse_auth_log(_read_lines(path), path=path, year=year)
        events += ev
        stats.append(st)
    for path in windows:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            ev, st = parse_windows_events(fh.read(), path=path)
        events += ev
        stats.append(st)
    for path in web:
        ev, st = parse_web_access(_read_lines(path), path=path, host=web_host or Path(path).name)
        events += ev
        stats.append(st)
    return events, stats


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loganalyzer", description="Parse security logs, detect suspicious activity, write incident reports.")
    p.add_argument("--version", action="version", version="loganalyzer " + __version__)
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze log files and write reports")
    a.add_argument("--auth", action="append", default=[], metavar="FILE", help="Linux auth.log (repeatable)")
    a.add_argument("--windows", action="append", default=[], metavar="FILE", help="Windows Security export, .csv or .json (repeatable)")
    a.add_argument("--web", action="append", default=[], metavar="FILE", help="nginx/Apache combined access log (repeatable)")
    a.add_argument("--web-host", metavar="NAME", help="host name to record for web logs (access logs carry none; default: the file name)")
    a.add_argument("--rules", default=str(DEFAULT_RULES_PATH), help="rule file (default: rules/detection_rules.json)")
    a.add_argument("--year", type=int, default=None, help="year for syslog timestamps that have none (default: current year)")
    a.add_argument("--out-json", metavar="FILE", help="write the JSON report (also what the dashboard loads)")
    a.add_argument("--out-md", metavar="FILE", help="write the Markdown incident report")
    a.add_argument("--ignore-ip", action="append", default=[], metavar="IP", help="exclude events from this IP (e.g. your own scanner); repeatable")
    a.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low", help="only report alerts at or above this severity")
    a.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit with status 2 if any alert is at or above this severity (for CI/cron use)")
    a.add_argument("--synthetic", action="store_true", help="label the report as synthetic data")
    a.add_argument("--quiet", action="store_true", help="no console summary")
    a.add_argument("--no-colour", action="store_true", help="disable ANSI colours")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("list-rules", help="print the loaded detection rules")
    r.add_argument("--rules", default=str(DEFAULT_RULES_PATH))
    r.set_defaults(func=cmd_list_rules)

    v = sub.add_parser("validate-rules", help="validate a rule file and exit non-zero if it is broken")
    v.add_argument("--rules", default=str(DEFAULT_RULES_PATH))
    v.set_defaults(func=cmd_validate)

    g = sub.add_parser("generate", help="write the SYNTHETIC sample logs and ground truth")
    g.add_argument("--out", default="data/synthetic", help="output directory")
    g.add_argument("--seed", type=int, default=1337)
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("demo", help="generate synthetic logs, analyze them, write reports and dashboard data, then self-check")
    d.add_argument("--data-dir", default="data/synthetic")
    d.add_argument("--reports-dir", default="reports")
    d.add_argument("--dashboard-json", default="dashboard/data/alerts.json")
    d.add_argument("--seed", type=int, default=1337)
    d.add_argument("--rules", default=str(DEFAULT_RULES_PATH))
    d.set_defaults(func=cmd_demo)
    return p


def _filter_min_severity(result: AnalysisResult, minimum: str) -> None:
    keep = SEVERITY_ORDER[minimum]
    result.alerts = [a for a in result.alerts if SEVERITY_ORDER[a.severity] >= keep]
    alert_ids = {a.id for a in result.alerts}
    for inc in result.incidents:
        inc.alert_ids = [i for i in inc.alert_ids if i in alert_ids]
    result.incidents = [i for i in result.incidents if i.alert_ids]


def print_summary(report: dict, colour: bool, out=None) -> None:
    out = out or sys.stdout
    c = (lambda sev, text: "{}{}\033[0m".format(SEV_COLOUR[sev], text)) if colour else (lambda sev, text: text)
    s = report["summary"]
    sc = s["severity_counts"]
    print("Analysed {:,} events ({}) | {} alerts | {} incidents".format(
        s["events_total"], ", ".join("{}={}".format(k, v) for k, v in sorted(s["events_by_source"].items())),
        s["alerts_total"], s["incidents_total"]), file=out)
    print("Severity: " + "  ".join(c(k, "{} {}".format(k.upper(), sc[k])) for k in ("critical", "high", "medium", "low")), file=out)
    for inp in report["meta"]["inputs"]:
        if inp["malformed"]:
            print("  warning: {} lines in {} could not be parsed".format(inp["malformed"], inp["path"]), file=out)
    if report["incidents"]:
        print("\nIncidents:", file=out)
        for inc in report["incidents"]:
            print("  {} {} {}".format(inc["id"], c(inc["severity"], "[{:^8}]".format(inc["severity"].upper())), inc["title"]), file=out)
    print("\nAlerts:", file=out)
    for a in sorted(report["alerts"], key=lambda x: (-SEVERITY_ORDER[x["severity"]], x["first_seen"])):
        print("  {} {} {} {} {}  ips={} n={}".format(
            a["id"], c(a["severity"], "[{:^8}]".format(a["severity"].upper())), a["rule_id"].ljust(8),
            a["first_seen"].replace("T", " "), a["title"], ",".join(a["source_ips"][:2]) or "-", a["count"]), file=out)


def cmd_analyze(args: argparse.Namespace) -> int:
    if not (args.auth or args.windows or args.web):
        print("error: give at least one of --auth, --windows, --web", file=sys.stderr)
        return EXIT_USAGE
    try:
        rules = load_rules(args.rules)
        events, stats = load_events(args.auth, args.windows, args.web, args.year, args.web_host)
    except (RuleError, OSError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE
    result = analyze(events, rules, stats, ignore_ips=args.ignore_ip)
    _filter_min_severity(result, args.min_severity)
    report = build_report(result, synthetic=args.synthetic)
    if args.out_json:
        write_json(report, args.out_json)
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(report), encoding="utf-8")
    if not args.quiet:
        print_summary(report, colour=sys.stdout.isatty() and not args.no_colour)
        for label, path in (("JSON", args.out_json), ("Markdown", args.out_md)):
            if path:
                print("{} report written to {}".format(label, path))
    if args.fail_on and any(SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.fail_on] for a in result.alerts):
        return EXIT_ALERTS
    return EXIT_OK


def cmd_list_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE
    print("{:<9} {:<9} {:<26} {:<10} {}".format("ID", "SEVERITY", "TYPE", "SOURCES", "MITRE / NAME"))
    for r in rules:
        print("{:<9} {:<9} {:<26} {:<10} {} | {}".format(
            r.id, r.severity, r.type, ",".join(r.sources), ",".join(m["id"] for m in r.mitre), r.name))
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print("INVALID: {}".format(exc), file=sys.stderr)
        return EXIT_USAGE
    print("OK: {} rules valid ({})".format(len(rules), args.rules))
    return EXIT_OK


def cmd_generate(args: argparse.Namespace) -> int:
    paths = synthetic.generate(args.out, seed=args.seed)
    for name, path in paths.items():
        print("wrote {} ({:,} bytes)".format(path, path.stat().st_size))
    return EXIT_OK


def cmd_demo(args: argparse.Namespace) -> int:
    paths = synthetic.generate(args.data_dir, seed=args.seed)
    rules = load_rules(args.rules)
    events, stats = load_events([str(paths["auth"])], [str(paths["windows_csv"]), str(paths["windows_json"])],
                                [str(paths["web"])], year=2026, web_host=synthetic.WEB_HOST)
    result = analyze(events, rules, stats)
    report = build_report(result, synthetic=True, generated_at=datetime(2026, 10, 18, 9, 0, 0))
    reports = Path(args.reports_dir)
    reports.mkdir(parents=True, exist_ok=True)
    write_json(report, str(reports / "alerts.json"))
    (reports / "incident_report.md").write_text(render_markdown(report), encoding="utf-8")
    Path(args.dashboard_json).parent.mkdir(parents=True, exist_ok=True)
    write_json(report, args.dashboard_json)
    print_summary(report, colour=False)
    ev = evaluate(report, paths["truth"])
    (reports / "evaluation.json").write_text(json.dumps(ev, indent=2) + "\n", encoding="utf-8")
    print("\n" + format_evaluation(ev))
    print("\nWrote {}/alerts.json, {}/incident_report.md, {}".format(args.reports_dir, args.reports_dir, args.dashboard_json))
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
