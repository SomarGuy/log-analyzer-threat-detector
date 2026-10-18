from datetime import datetime, timedelta

from loganalyzer import engine
from loganalyzer.alerts import Alert, make_alert, sample_events
from loganalyzer.models import LOGIN_FAILED, LOGIN_SUCCESS, Event
from tests.conftest import T, ev


def test_sample_events_keeps_first_and_last_and_is_bounded():
    evs = [ev(LOGIN_FAILED, ts=T() + timedelta(seconds=i)) for i in range(100)]
    picked = sample_events(evs, 12)
    assert len(picked) <= 12 and picked[0] is evs[0] and picked[-1] is evs[-1]
    assert sample_events(evs[:5], 12) == evs[:5]
    assert sample_events(evs, 1) == [evs[0]]


def test_make_alert_orders_events_and_truncates_evidence(rule_by_id):
    evs = [ev(LOGIN_FAILED, ts=T(s=i), user="u", src_ip="1.1.1.1", raw="x" * 1000) for i in (5, 1, 3)]
    a = make_alert(rule_by_id["AUTH-001"], evs)
    assert a.first_seen == T(s=1) and a.last_seen == T(s=5) and a.count == 3
    assert all(len(line) <= 400 for line in a.evidence)
    d = a.as_dict()
    assert d["duration_seconds"] == 4 and d["first_seen"] == "2026-10-13T02:00:01"


def test_synthetic_dataset_alert_counts(synth_report):
    s = synth_report["summary"]
    assert s["alerts_total"] == len(synth_report["alerts"]) == sum(s["severity_counts"].values())
    assert s["severity_counts"]["critical"] >= 4
    assert s["events_total"] == sum(s["events_by_source"].values())
    assert set(s["events_by_source"]) == {"auth", "windows", "web"}


def test_incident_correlation_chain_for_ssh_compromise(synth_report):
    inc = next(i for i in synth_report["incidents"] if "198.51.100.77" in i["source_ips"])
    rules = {a["rule_id"] for a in synth_report["alerts"] if a["id"] in inc["alert_ids"]}
    # brute force -> success -> off-hours -> new account -> admin rights, on one story
    assert {"AUTH-001", "AUTH-003", "AUTH-004", "ACCT-001", "ACCT-002"} <= rules
    assert inc["severity"] == "critical"
    assert inc["tactics"].index("Initial Access") < inc["tactics"].index("Persistence") or "Credential Access" in inc["tactics"]


def test_incident_links_ip_less_windows_alerts_by_host_and_time(synth_report):
    inc = next(i for i in synth_report["incidents"] if "198.51.100.23" in i["source_ips"])
    rules = {a["rule_id"] for a in synth_report["alerts"] if a["id"] in inc["alert_ids"]}
    assert {"WIN-001", "WIN-002", "WIN-003", "WIN-004", "ACCT-002"} <= rules


def test_same_ip_across_log_sources_is_one_incident(synth_report):
    inc = next(i for i in synth_report["incidents"] if "203.0.113.45" in i["source_ips"])
    sources = {s for a in synth_report["alerts"] if a["id"] in inc["alert_ids"] for s in a["log_sources"]}
    assert sources == {"auth", "web"}


def test_alert_incident_ids_are_consistent(synth_report):
    inc_ids = {i["id"] for i in synth_report["incidents"]}
    by_id = {a["id"]: a for a in synth_report["alerts"]}
    for inc in synth_report["incidents"]:
        for aid in inc["alert_ids"]:
            assert by_id[aid]["incident_id"] == inc["id"]
    assert all(a["incident_id"] in inc_ids | {""} for a in synth_report["alerts"])


def test_single_low_alert_does_not_become_incident(synth_report):
    scraper = next(a for a in synth_report["alerts"] if a["rule_id"] == "WEB-007")
    assert scraper["incident_id"] == ""


def test_top_attackers_sorted_and_flagged_internal(synth_report):
    rows = synth_report["summary"]["top_attackers"]
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    keys = [(-order[r["max_severity"]], -r["alerts"]) for r in rows]
    assert keys == sorted(keys)
    flags = {r["ip"]: r["internal"] for r in rows}
    assert flags["198.51.100.77"] is False and flags["10.20.0.54"] is True


def test_is_internal():
    assert engine.is_internal("10.1.2.3") and engine.is_internal("192.168.0.1") and engine.is_internal("172.16.5.5")
    assert engine.is_internal("127.0.0.1") and engine.is_internal("::1") and engine.is_internal("fc00::1")
    assert not engine.is_internal("203.0.113.5") and not engine.is_internal("8.8.8.8")   # documentation range counts as external
    assert not engine.is_internal("not-an-ip") and not engine.is_internal("2001:db8::1")


def test_mitre_summary_is_in_kill_chain_order(synth_report):
    tactics = [m["tactic"] for m in synth_report["summary"]["mitre"]]
    order = engine.TACTIC_ORDER
    assert tactics == sorted(tactics, key=order.index)
    ids = {m["id"] for m in synth_report["summary"]["mitre"]}
    assert {"T1110.001", "T1110.003", "T1078", "T1136.001", "T1190", "T1595.002", "T1059.001"} <= ids


def test_volume_by_hour_counts_every_event():
    evs = [ev(LOGIN_FAILED, "auth", T(h=1, m=5)), ev(LOGIN_FAILED, "web", T(h=1, m=50)), ev(LOGIN_FAILED, "auth", T(h=2))]
    vol = engine.volume_by_hour(evs)
    assert [(v["hour"], v["total"]) for v in vol] == [("2026-10-13T01:00:00", 2), ("2026-10-13T02:00:00", 1)]
    assert vol[0]["auth"] == 1 and vol[0]["web"] == 1


def test_analyze_empty_input(rules):
    res = engine.analyze([], rules)
    assert res.alerts == [] and res.incidents == [] and res.stats["time_range"] == []


def test_correlate_standalone_critical_gets_its_own_incident():
    from loganalyzer.rules import Rule
    rule = Rule(id="X", name="x", type="account_created", severity="critical", sources=["auth"],
                mitre=[{"id": "T1136.001", "name": "n", "tactic": "Persistence"}])
    e = ev("account_created", "auth", T(), host="h", user="u")
    a = make_alert(rule, [e])
    a.id = "ALR-001"
    incidents = engine.correlate([a])
    assert len(incidents) == 1 and "host h" in incidents[0].title and a.incident_id == "INC-01"
