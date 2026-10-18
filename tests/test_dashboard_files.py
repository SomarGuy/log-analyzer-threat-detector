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
    csp = headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "style-src 'self'" in csp and "font-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "http" not in csp
    root = json.loads((DASH.parent / "vercel.json").read_text())   # the root config is what a repo import uses
    root_csp = {h["key"]: h["value"] for rule in root["headers"] for h in rule["headers"]}["Content-Security-Policy"]
    assert root_csp == csp


def test_index_contains_synthetic_notice_and_required_sections():
    html = (DASH / "index.html").read_text()
    assert "SYNTHETIC DATA" in html
    for needle in ("id=\"timeline\"", "id=\"top-ips\"", "id=\"mitre-table\"", "id=\"alert-table\"", "id=\"drawer\"", "id=\"kpis\"",
                   "id=\"incidents\"", "id=\"tail\"", "id=\"statusbar\"", "id=\"help\"", "id=\"keybar\"", "id=\"f-export\"", "id=\"file-input\""):
        assert needle in html


def test_console_pieces_are_wired_up():
    """Status bar, event tail, key bar and the keyboard shortcuts exist in the code, not just in the HTML."""
    js = (DASH / "app.js").read_text()
    for key in ('case "j"', 'case "k"', 'key === "/"', 'key === "?"', 'case "p"', 'case "e"', 'case "r"', 'case "c"'):
        assert key in js, key
    assert "tailReset" in js and "tailTick" in js and "exportCsv" in js and "ticketNote" in js
    html = (DASH / "index.html").read_text()
    for label in ("Alerts", "Timeline", "Event tail", "Top IPs", "Incidents", "MITRE ATT&amp;CK", "Why I built this", "Export CSV", "Load your own alerts.json"):
        assert label in html, label


def test_bundled_font_and_box_drawing_borders():
    css = (DASH / "style.css").read_text()
    html = (DASH / "index.html").read_text()
    urls = re.findall(r"url\(\"?([^)\"]+)\"?\)", css)
    assert urls and all(not u.startswith(("http", "//")) for u in urls)      # no remote fonts (strict CSP)
    for u in urls:
        assert (DASH / u).is_file(), u
    assert "@import" not in css
    assert (DASH / "fonts" / "LICENSE-font.txt").is_file()
    assert "┌" in html and "└" in html and "┘" in html and "─" in css      # panels are drawn with box-drawing characters
    assert "background: var(--bg)" in css and "--bg: #060906" in css           # dark console identity


def test_why_i_built_this_note_is_personal_and_plain():
    html = (DASH / "index.html").read_text()
    note = html[html.index('id="sec-why"'):html.index("</section>", html.index('id="sec-why"'))]
    for needle in ("I'm a CS student in Toronto", "password spraying", "What I'd improve"):
        assert needle in note, needle
    assert re.search(r"\bI\b", note)
    for banned in ("leverage", "robust", "comprehensive", "seamless", "cutting-edge", "passionate", "synergy"):
        assert banned not in note.lower(), banned


def test_no_em_dashes_in_dashboard_or_readme():
    for f in (DASH / "index.html", DASH / "app.js", DASH / "style.css", DASH.parent / "README.md"):
        assert "\u2014" not in f.read_text(), f.name


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
