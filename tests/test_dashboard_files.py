"""Static checks on the dashboard so a broken deploy folder is caught without a browser."""
import json
import re
from pathlib import Path

DASH = Path(__file__).resolve().parent.parent / "dashboard"


def test_index_references_existing_assets():
    html = (DASH / "index.html").read_text()
    for ref in re.findall(r'(?:src|href)="([^"#:]+)"', html):
        assert (DASH / ref).exists(), ref


def test_no_inline_scripts_or_handlers_so_csp_can_be_strict():
    html = (DASH / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert 'style="' not in html


def test_app_never_uses_innerhtml():
    js = (DASH / "app.js").read_text()
    assert "innerHTML" not in js and "outerHTML" not in js and "document.write" not in js and "eval(" not in js


def test_vercel_json_is_valid_and_sets_security_headers():
    cfg = json.loads((DASH / "vercel.json").read_text())
    headers = {h["key"]: h["value"] for rule in cfg["headers"] for h in rule["headers"]}
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"] and "script-src 'self'" in headers["Content-Security-Policy"]


def test_index_contains_synthetic_notice_and_required_sections():
    html = (DASH / "index.html").read_text()
    assert "SYNTHETIC DATA" in html
    for needle in ("id=\"timeline\"", "id=\"top-ips\"", "id=\"mitre-table\"", "id=\"alert-table\"", "id=\"drawer\"", "id=\"kpis\""):
        assert needle in html


def test_bundled_alerts_json_matches_dashboard_expectations():
    data = json.loads((DASH / "data" / "alerts.json").read_text())
    assert data["meta"]["synthetic"] is True
    assert data["alerts"] and data["summary"]["mitre"] and data["summary"]["top_attackers"] and data["summary"]["volume_by_hour"]
    assert all(a["severity"] in ("critical", "high", "medium", "low") for a in data["alerts"])
    assert data["summary"]["alerts_total"] == len(data["alerts"])
    assert "/workspace/" not in (DASH / "data" / "alerts.json").read_text()   # no local build paths leaked


def test_readme_documents_every_rule_and_no_rule_is_missing():
    from loganalyzer.rules import load_rules
    readme = (DASH.parent / "README.md").read_text()
    for rule in load_rules():
        assert "`{}`".format(rule.id) in readme, rule.id


def test_readme_numbers_match_committed_reports():
    import json as _json
    readme = (DASH.parent / "README.md").read_text()
    report = _json.loads((DASH.parent / "reports" / "alerts.json").read_text())
    s = report["summary"]
    assert "{} alerts | {} incidents".format(s["alerts_total"], s["incidents_total"]) in readme
    assert "Analysed {:,} events".format(s["events_total"]) in readme
    ev = _json.loads((DASH.parent / "reports" / "evaluation.json").read_text())
    assert "{}/{}".format(ev["scenarios_fully_detected"], ev["scenarios_total"]) in readme
    assert "{}/{}".format(ev["expected_alerts_detected"], ev["expected_alerts"]) in readme
