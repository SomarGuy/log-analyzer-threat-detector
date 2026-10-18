import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from loganalyzer import cli, synthetic
from loganalyzer.evaluate import evaluate, format_evaluation
from loganalyzer.report import SCHEMA_VERSION, render_markdown, write_json

ROOT = Path(__file__).resolve().parent.parent


# ----------------------------------------------------------------------------- report


def test_report_schema(synth_report):
    r = synth_report
    assert r["schema_version"] == SCHEMA_VERSION
    assert set(r) == {"schema_version", "meta", "summary", "incidents", "alerts", "rules"}
    assert r["meta"]["synthetic"] is True and "SYNTHETIC" in r["meta"]["synthetic_notice"]
    assert all(set(i) >= {"path", "source", "lines", "parsed", "ignored", "malformed"} for i in r["meta"]["inputs"])
    required = {"id", "rule_id", "title", "severity", "first_seen", "last_seen", "count", "source_ips", "users", "hosts",
                "mitre", "recommended_response", "timeline", "evidence", "details", "description", "incident_id", "log_sources"}
    for a in r["alerts"]:
        assert required <= set(a)
        assert a["severity"] in {"critical", "high", "medium", "low"}
        assert a["first_seen"] <= a["last_seen"] and a["count"] >= 1
        assert a["timeline"] and a["evidence"] and a["recommended_response"] and a["mitre"]
        ts = [t["ts"] for t in a["timeline"]]
        assert ts == sorted(ts)


def test_report_is_valid_json_roundtrip(synth_report, tmp_path):
    p = tmp_path / "r.json"
    write_json(synth_report, str(p))
    assert json.loads(p.read_text()) == synth_report


def test_every_alert_in_report_has_a_timeline_and_ips_where_applicable(synth_report):
    web = [a for a in synth_report["alerts"] if a["rule_id"].startswith("WEB")]
    assert web and all(a["source_ips"] for a in web)


def test_no_malformed_lines_in_synthetic_inputs(synth_report):
    assert sum(i["malformed"] for i in synth_report["meta"]["inputs"]) == 0


def test_markdown_report_structure(synth_report):
    md = render_markdown(synth_report)
    for heading in ("# Log Analyzer incident report", "## Executive summary", "## Incidents", "## Top source IPs",
                    "## MITRE ATT&CK coverage", "## Alerts", "## Input files and parse quality"):
        assert heading in md
    assert md.count("### ALR-") == synth_report["summary"]["alerts_total"]
    assert "SYNTHETIC DATA" in md
    assert "https://attack.mitre.org/techniques/T1110/003/" in md
    assert "Recommended response:" in md


def test_markdown_neutralises_code_fence_in_evidence(synth_report):
    import copy
    r = copy.deepcopy(synth_report)
    r["alerts"][0]["evidence"] = ["evil ``` <script>alert(1)</script> | pipe"]
    md = render_markdown(r)
    assert md.count("```") % 2 == 0
    assert "evil ''' <script>" in md


def test_markdown_for_empty_report(rules):
    from loganalyzer.engine import analyze
    from loganalyzer.report import build_report
    md = render_markdown(build_report(analyze([], rules)))
    assert "No techniques observed." in md and "No alerts with a source IP." in md and "**Alerts:** 0" in md


# ----------------------------------------------------------------------------- synthetic data + evaluation


def test_synthetic_files_are_labelled(synth_dir):
    for name in ("auth.log", "access.log", "windows_security_dc01.csv"):
        assert (synth_dir / name).read_text().splitlines()[0].startswith("# SYNTHETIC DATA")
    assert "SYNTHETIC DATA" in json.loads((synth_dir / "windows_security_ws12.json").read_text())["_synthetic_notice"]
    assert "SYNTHETIC DATA" in json.loads((synth_dir / "ground_truth.json").read_text())["_synthetic_notice"]


def test_synthetic_generation_is_deterministic(tmp_path):
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    synthetic.generate(a, seed=5)
    synthetic.generate(b, seed=5)
    synthetic.generate(c, seed=6)
    for name in ("auth.log", "access.log", "windows_security_dc01.csv", "windows_security_ws12.json", "ground_truth.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
    assert (a / "access.log").read_bytes() != (c / "access.log").read_bytes()


def test_synthetic_ips_are_documentation_or_private_ranges(synth_dir):
    web = [ln.split(" ")[0] for ln in (synth_dir / "access.log").read_text().splitlines() if not ln.startswith("#")]
    auth = re.findall(r" from (\S+) port ", (synth_dir / "auth.log").read_text())
    win = re.findall(r",(\d+\.\d+\.\d+\.\d+),", (synth_dir / "windows_security_dc01.csv").read_text())
    allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "10.")
    ips = set(web) | set(auth) | set(win)
    assert len(ips) > 100
    assert [ip for ip in ips if not ip.startswith(allowed)] == []


def test_every_injected_scenario_is_detected_and_nothing_unexpected_fires(synth_report, synth_dir):
    ev = evaluate(synth_report, synth_dir / "ground_truth.json")
    assert ev["scenarios_total"] >= 12
    assert ev["scenarios_fully_detected"] == ev["scenarios_total"], format_evaluation(ev)
    assert ev["expected_alerts_detected"] == ev["expected_alerts"]
    assert ev["unexpected_alerts"] == [], ev["unexpected_alerts"]


def test_evaluation_reports_a_miss(synth_report, synth_dir):
    import copy
    r = copy.deepcopy(synth_report)
    r["alerts"] = [a for a in r["alerts"] if a["rule_id"] != "WEB-004"]
    ev = evaluate(r, synth_dir / "ground_truth.json")
    assert ev["scenarios_fully_detected"] == ev["scenarios_total"] - 1
    assert "MISS" in format_evaluation(ev) and "missing" in format_evaluation(ev)


def test_benign_noise_is_quiet(synth_report):
    """Googlebot 404s, the ipconfig /all admin, svc_monitor night logons and typos must not alert."""
    ips = {ip for a in synth_report["alerts"] for ip in a["source_ips"]}
    assert "192.0.2.8" not in ips and "192.0.2.5" not in ips
    assert not [a for a in synth_report["alerts"] if a["rule_id"] == "WIN-004" and "helpdesk" in a["users"]]
    assert not [a for a in synth_report["alerts"] if "svc_monitor" in a["users"]]


# ----------------------------------------------------------------------------- CLI


def run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_analyze_writes_reports(synth_dir, tmp_path, capsys):
    j, m = tmp_path / "a.json", tmp_path / "a.md"
    code, out, _ = run(["analyze", "--auth", str(synth_dir / "auth.log"), "--windows", str(synth_dir / "windows_security_dc01.csv"),
                        "--windows", str(synth_dir / "windows_security_ws12.json"), "--web", str(synth_dir / "access.log"),
                        "--year", "2026", "--synthetic", "--out-json", str(j), "--out-md", str(m), "--web-host", "w1"], capsys)
    assert code == 0
    assert "Incidents:" in out and "CRITICAL" in out and "JSON report written" in out
    report = json.loads(j.read_text())
    assert report["meta"]["synthetic"] is True and report["summary"]["alerts_total"] > 20
    assert any(h == "w1" for a in report["alerts"] for h in a["hosts"])
    assert m.read_text().startswith("# Log Analyzer incident report")


def test_cli_requires_input(capsys):
    code, _, err = run(["analyze"], capsys)
    assert code == cli.EXIT_USAGE and "at least one" in err


def test_cli_missing_file_and_bad_rules(synth_dir, tmp_path, capsys):
    code, _, err = run(["analyze", "--auth", str(tmp_path / "nope.log")], capsys)
    assert code == cli.EXIT_USAGE and "error:" in err
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    code, _, err = run(["analyze", "--auth", str(synth_dir / "auth.log"), "--rules", str(bad)], capsys)
    assert code == cli.EXIT_USAGE and "not valid JSON" in err


def test_cli_fail_on_exit_codes(synth_dir, tmp_path, capsys):
    base = ["analyze", "--web", str(synth_dir / "access.log"), "--quiet", "--year", "2026"]
    assert run(base + ["--fail-on", "critical"], capsys)[0] == cli.EXIT_ALERTS      # WEB-002/004 are critical
    assert run(base, capsys)[0] == 0                                                 # no --fail-on
    empty = tmp_path / "quiet.log"
    empty.write_text('1.1.1.1 - - [13/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0"\n')
    assert run(["analyze", "--web", str(empty), "--quiet", "--fail-on", "low"], capsys)[0] == 0


def test_cli_min_severity_filters_alerts_and_incidents(synth_dir, tmp_path, capsys):
    j = tmp_path / "hi.json"
    run(["analyze", "--auth", str(synth_dir / "auth.log"), "--web", str(synth_dir / "access.log"), "--year", "2026",
         "--min-severity", "high", "--out-json", str(j), "--quiet"], capsys)
    report = json.loads(j.read_text())
    assert report["alerts"] and all(a["severity"] in ("high", "critical") for a in report["alerts"])
    ids = {a["id"] for a in report["alerts"]}
    assert all(set(i["alert_ids"]) <= ids and i["alert_ids"] for i in report["incidents"])


def test_cli_ignore_ip(synth_dir, tmp_path, capsys):
    j = tmp_path / "i.json"
    run(["analyze", "--web", str(synth_dir / "access.log"), "--ignore-ip", "198.51.100.150", "--out-json", str(j), "--quiet"], capsys)
    assert "198.51.100.150" not in {ip for a in json.loads(j.read_text())["alerts"] for ip in a["source_ips"]}


def test_cli_warns_about_malformed_lines(tmp_path, capsys):
    p = tmp_path / "access.log"
    p.write_text("garbage line\n" * 3)
    code, out, _ = run(["analyze", "--web", str(p)], capsys)
    assert code == 0 and "3 lines" in out and "could not be parsed" in out


def test_cli_list_and_validate_rules(tmp_path, capsys):
    code, out, _ = run(["list-rules"], capsys)
    assert code == 0 and "AUTH-001" in out and "T1110.001" in out
    code, out, _ = run(["validate-rules"], capsys)
    assert code == 0 and out.startswith("OK:")
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"rules": [{"id": "X"}]}))
    assert run(["validate-rules", "--rules", str(bad)], capsys)[0] == cli.EXIT_USAGE
    assert run(["list-rules", "--rules", str(bad)], capsys)[0] == cli.EXIT_USAGE


def test_cli_generate(tmp_path, capsys):
    code, out, _ = run(["generate", "--out", str(tmp_path / "g"), "--seed", "3"], capsys)
    assert code == 0 and (tmp_path / "g" / "auth.log").exists() and "wrote" in out


def test_cli_demo_end_to_end(tmp_path, capsys):
    code, out, _ = run(["demo", "--data-dir", str(tmp_path / "d"), "--reports-dir", str(tmp_path / "r"),
                        "--dashboard-json", str(tmp_path / "dash" / "alerts.json")], capsys)
    assert code == 0
    assert "scenarios fully detected : 12/12" in out and "unexpected alerts        : 0" in out
    for f in ("r/alerts.json", "r/incident_report.md", "r/evaluation.json", "dash/alerts.json"):
        assert (tmp_path / f).stat().st_size > 100


def test_python_dash_m_entrypoint():
    res = subprocess.run([sys.executable, "-m", "loganalyzer", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert res.returncode == 0 and "loganalyzer" in res.stdout


def test_colour_output_only_when_requested(synth_report):
    import io
    buf = io.StringIO()
    cli.print_summary(synth_report, colour=True, out=buf)
    assert "\033[" in buf.getvalue()
    buf = io.StringIO()
    cli.print_summary(synth_report, colour=False, out=buf)
    assert "\033[" not in buf.getvalue()


def test_committed_sample_files_match_what_the_generator_produces(synth_dir):
    """The checked-in data/ and reports/ must be reproducible with `python -m loganalyzer demo`."""
    for name in ("auth.log", "access.log", "windows_security_dc01.csv", "windows_security_ws12.json", "ground_truth.json"):
        assert (ROOT / "data" / "synthetic" / name).read_bytes() == (synth_dir / name).read_bytes(), name


def test_committed_alerts_json_matches_a_fresh_run(synth_report):
    committed = json.loads((ROOT / "reports" / "alerts.json").read_text())
    assert committed["alerts"] == synth_report["alerts"]
    assert committed["summary"] == synth_report["summary"]
    assert (ROOT / "dashboard" / "data" / "alerts.json").read_bytes() == (ROOT / "reports" / "alerts.json").read_bytes()
