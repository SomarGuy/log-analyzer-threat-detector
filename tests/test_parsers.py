import json
from datetime import datetime

from loganalyzer.models import (ACCOUNT_CREATED, GROUP_ADD, HTTP_REQUEST, LOGIN_FAILED, LOGIN_SUCCESS,
                                PRIVILEGE_ASSIGNED, PROCESS_CREATED)
from loganalyzer.parsers import parse_auth_log, parse_web_access, parse_windows_events
from loganalyzer.parsers import auth_log, web_access, windows

# ----------------------------------------------------------------------------- auth.log


def one(line, year=2026):
    events, stats = parse_auth_log([line], year=year)
    return events, stats


def test_failed_password_valid_user():
    events, _ = one("Oct 13 02:10:03 host sshd[123]: Failed password for root from 203.0.113.45 port 51234 ssh2")
    e = events[0]
    assert (e.kind, e.user, e.src_ip, e.host) == (LOGIN_FAILED, "root", "203.0.113.45", "host")
    assert e.ts == datetime(2026, 10, 13, 2, 10, 3)
    assert e.extra["invalid_user"] is False


def test_failed_password_invalid_user_counts_once():
    lines = [
        "Oct 13 02:10:03 host sshd[123]: Invalid user admin from 203.0.113.45 port 51234",
        "Oct 13 02:10:03 host sshd[123]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2",
    ]
    events, stats = parse_auth_log(lines, year=2026)
    assert len(events) == 1 and events[0].extra["invalid_user"] is True
    assert stats.ignored == 1 and stats.parsed == 1


def test_accepted_password_and_publickey():
    events, _ = parse_auth_log([
        "Oct  5 09:00:01 h sshd[1]: Accepted password for deploy from 10.0.0.5 port 22 ssh2",
        "Oct  5 09:00:02 h sshd[2]: Accepted publickey for jlee from 10.0.0.6 port 22 ssh2: RSA SHA256:abc"], year=2026)
    assert [(e.kind, e.user, e.extra["method"]) for e in events] == [
        (LOGIN_SUCCESS, "deploy", "password"), (LOGIN_SUCCESS, "jlee", "publickey")]
    assert events[0].ts.day == 5   # single-digit, space-padded day


def test_ipv6_source():
    events, _ = one("Oct 13 02:10:03 h sshd[1]: Failed password for bob from 2001:db8::1 port 4000 ssh2")
    assert events[0].src_ip == "2001:db8::1"


def test_useradd_and_group_add_track_sudo_actor():
    lines = [
        "Oct 14 03:43:40 h sudo[7001]:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m x",
        "Oct 14 03:43:41 h useradd[7002]: new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash",
        "Oct 14 03:44:06 h usermod[7011]: add 'sysupdate' to group 'sudo'",
        "Oct 14 03:44:06 h usermod[7011]: add 'sysupdate' to shadow group 'sudo'",
        "Oct 14 03:44:07 h usermod[7011]: add 'sysupdate' to group 'staff'",
    ]
    events, stats = parse_auth_log(lines, year=2026)
    kinds = [e.kind for e in events]
    assert kinds == [ACCOUNT_CREATED, GROUP_ADD, GROUP_ADD]
    assert events[0].user == "sysupdate" and events[0].extra["actor"] == "deploy"
    assert events[1].extra == {"group": "sudo", "privileged": True, "actor": "deploy"}
    assert events[2].extra["privileged"] is False
    assert stats.ignored == 2   # sudo line + shadow-group line


def test_gpasswd_style_group_message():
    events, _ = one("Oct 14 03:44:06 h gpasswd[5]: user 'eve' added to group 'wheel'")
    assert events[0].kind == GROUP_ADD and events[0].extra["privileged"] is True


def test_rfc3339_timestamps_with_offset():
    line = "2026-10-13T02:10:03.123456-04:00 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    events, _ = parse_auth_log([line])
    assert events[0].ts == datetime(2026, 10, 13, 2, 10, 3)


def test_year_rollover_december_to_january():
    lines = ["Dec 31 23:59:59 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2",
             "Jan  1 00:00:05 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"]
    events, _ = parse_auth_log(lines, year=2026)
    assert events[0].ts.year == 2026 and events[1].ts.year == 2027


def test_comments_blank_and_garbage_lines():
    lines = ["# SYNTHETIC DATA", "", "this is not a log line", "Oct 13 02:10:03 h cron[1]: (root) CMD (run)",
             "Foo 99 99:99:99 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"]
    events, stats = parse_auth_log(lines, year=2026)
    assert events == []
    assert (stats.lines, stats.ignored, stats.malformed) == (5, 3, 2)


def test_invalid_calendar_date_is_malformed():
    kind, e = auth_log.parse_line("Feb 31 10:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2", 2026)
    assert kind == "malformed" and e is None


def test_default_year_is_current_year():
    events, _ = parse_auth_log(["Oct 13 02:10:03 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"])
    assert events[0].ts.year == datetime.now().year


# ----------------------------------------------------------------------------- Windows

CSV_HEAD = "TimeCreated,EventID,Computer,SubjectUserName,TargetUserName,TargetDomainName,LogonType,IpAddress,WorkstationName,Status,SubStatus,NewProcessName,CommandLine,ParentProcessName,PrivilegeList,TargetGroup\n"


def test_windows_csv_all_event_ids():
    rows = [
        "2026-10-14T14:02:11,4625,DC1,,alice,CORP,3,198.51.100.23,-,0xC000006D,0xC000006A,,,,,",
        "2026-10-14T14:33:20,4624,DC1,,svc_backup,CORP,3,198.51.100.23,PC1,,,,,,,",
        "2026-10-14T14:33:20,4672,DC1,svc_backup,,CORP,,,,,,,,,SeDebugPrivilege,",
        "2026-10-14T14:36:02,4688,DC1,svc_backup,,CORP,,,,,,C:\\Windows\\System32\\cmd.exe,cmd /c whoami /all,C:\\x.exe,,",
        "2026-10-14T14:41:01,4720,DC1,svc_backup,helpdesk_tmp,CORP,,,,,,,,,,",
        "2026-10-14T14:42:10,4732,DC1,svc_backup,helpdesk_tmp,CORP,,,,,,,,,,Administrators",
        "2026-10-14T14:42:11,4634,DC1,,x,CORP,,,,,,,,,,",
    ]
    events, stats = parse_windows_events("# comment\n" + CSV_HEAD + "\n".join(rows) + "\n", path="x.csv")
    assert [e.kind for e in events] == [LOGIN_FAILED, LOGIN_SUCCESS, PRIVILEGE_ASSIGNED, PROCESS_CREATED, ACCOUNT_CREATED, GROUP_ADD]
    assert events[0].extra["sub_status"] == "0xC000006A" and events[0].src_ip == "198.51.100.23"
    assert events[2].user == "svc_backup"
    assert events[3].extra["command_line"] == "cmd /c whoami /all"
    assert events[4].user == "helpdesk_tmp" and events[4].extra["actor"] == "svc_backup"
    assert events[5].extra["group"] == "Administrators" and events[5].extra["privileged"] is True
    assert stats.parsed == 6 and stats.ignored == 2 and stats.malformed == 0   # 4634 + comment line


def test_windows_csv_header_aliases_case_insensitive():
    text = "time,Id,MachineName,Target User Name,IP Address,Logon Type\n2026-10-14 08:00:00,4624,WS1,alice,10.0.0.5,2\n"
    events, _ = parse_windows_events(text, path="a.csv")
    assert events[0].user == "alice" and events[0].host == "WS1" and events[0].extra["logon_type"] == "2"


def test_windows_malformed_rows_counted():
    text = CSV_HEAD + "not-a-date,4625,DC1,,a,C,3,1.1.1.1,,,,,,,,\n2026-10-14T01:00:00,abc,DC1,,a,C,3,1.1.1.1,,,,,,,,\n"
    events, stats = parse_windows_events(text, path="a.csv")
    assert events == [] and stats.malformed == 2


def test_windows_csv_extra_fields_flagged_malformed():
    text = "TimeCreated,EventID\n2026-10-14T01:00:00,4625,surplus,fields\n"
    _, stats = parse_windows_events(text, path="a.csv")
    assert stats.malformed == 1


def test_windows_json_list_object_and_ndjson():
    rec = {"TimeCreated": "2026-10-14T08:00:00Z", "EventID": 4625, "TargetUserName": "bob", "IpAddress": "::ffff:5.6.7.8"}
    for text in (json.dumps([rec]), json.dumps({"events": [rec]}), json.dumps(rec) + "\n" + json.dumps(rec)):
        events, stats = parse_windows_events(text, path="e.json")
        assert events and events[0].src_ip == "5.6.7.8" and events[0].user == "bob"
        assert events[0].ts == datetime(2026, 10, 14, 8, 0, 0)


def test_windows_json_garbage_entries():
    events, stats = parse_windows_events('[1, {"TimeCreated": "2026-10-14T08:00:00", "EventID": 4624, "TargetUserName": "a"}]', path="e.json")
    assert len(events) == 1 and stats.malformed == 1
    events, stats = parse_windows_events("garbage\n{bad json}\n", path="e.json")
    assert events == [] and stats.malformed == 2
    events, stats = parse_windows_events("   ", path="e.json")
    assert events == [] and stats.lines == 0
    events, stats = parse_windows_events("42", path="e.json")
    assert stats.malformed == 1


def test_windows_format_guessed_from_content():
    text = json.dumps([{"TimeCreated": "2026-10-14T08:00:00", "EventID": 4624, "TargetUserName": "a"}])
    events, _ = parse_windows_events(text, path="export.txt")
    assert len(events) == 1
    events, _ = parse_windows_events(CSV_HEAD + "2026-10-14T08:00:00,4624,H,,a,C,2,,,,,,,,,\n", path="export.txt")
    assert len(events) == 1


def test_windows_timestamp_formats():
    p = windows.parse_timestamp
    assert p("2026-10-14T08:00:00.1234567Z") == datetime(2026, 10, 14, 8, 0, 0)
    assert p("10/14/2026 08:05:00 PM") == datetime(2026, 10, 14, 20, 5, 0)
    assert p("/Date(1792281600000)/") == datetime(2026, 10, 18, 0, 0, 0)
    assert p("2026-10-14 08:00:00+02:00") == datetime(2026, 10, 14, 8, 0, 0)
    assert p("") is None and p("yesterday") is None


def test_windows_loopback_and_dash_ips_cleared():
    for ip in ("-", "::1", "127.0.0.1", ""):
        text = "TimeCreated,EventID,TargetUserName,IpAddress\n2026-10-14T08:00:00,4624,a,{}\n".format(ip)
        events, _ = parse_windows_events(text, path="a.csv")
        assert events[0].src_ip == ""


# ----------------------------------------------------------------------------- web access

COMBINED = ('203.0.113.45 - - [13/Oct/2026:02:58:00 -0400] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"')


def test_combined_log_line():
    events, stats = parse_web_access([COMBINED], path="access.log", host="web1")
    e = events[0]
    assert e.kind == HTTP_REQUEST and e.src_ip == "203.0.113.45" and e.host == "web1"
    assert e.ts == datetime(2026, 10, 13, 2, 58, 0)
    assert (e.extra["method"], e.extra["path"], e.extra["status"], e.extra["bytes"]) == ("GET", "/admin", 404, 153)
    assert e.extra["user_agent"] == "gobuster/3.6" and e.extra["referer"] == ""
    assert stats.parsed == 1


def test_url_decoding_including_double_encoding():
    line = '1.2.3.4 - bob [13/Oct/2026:02:58:00 +0000] "GET /f?x=..%252f..%252fetc%252fpasswd HTTP/1.1" 200 10 "-" "curl/8"'
    e = parse_web_access([line])[0][0]
    assert "../../etc/passwd" in e.extra["decoded_path"]
    assert e.user == "bob"


def test_common_log_format_without_referer_and_ua():
    line = '1.2.3.4 - - [13/Oct/2026:02:58:00 +0000] "GET / HTTP/1.0" 200 -'
    e = parse_web_access([line])[0][0]
    assert e.extra["user_agent"] == "" and e.extra["bytes"] == 0


def test_dash_user_agent_becomes_empty():
    line = '1.2.3.4 - - [13/Oct/2026:02:58:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"'
    assert parse_web_access([line])[0][0].extra["user_agent"] == ""


def test_garbage_request_line_kept_for_pattern_rules():
    line = '1.2.3.4 - - [13/Oct/2026:02:58:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'
    e = parse_web_access([line])[0][0]
    assert e.extra["method"] == "" and "x16" in e.extra["path"]


def test_web_comments_blank_and_malformed():
    events, stats = parse_web_access(["# c", "", "garbage", '1.1.1.1 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"', COMBINED])
    assert len(events) == 1 and stats.malformed == 2 and stats.ignored == 2


def test_quotes_inside_user_agent():
    line = r'1.2.3.4 - - [13/Oct/2026:02:58:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla \"quoted\" agent"'
    assert parse_web_access([line])[0][0].extra["user_agent"] == r'Mozilla \"quoted\" agent'
