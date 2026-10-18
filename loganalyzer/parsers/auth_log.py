"""Parser for Linux ``/var/log/auth.log`` (Debian/Ubuntu) style SSH logs.

Understands both classic syslog timestamps (``Oct 13 02:14:07``, no year) and
RFC 3339 timestamps (``2026-10-13T02:14:07.123456-04:00``). Recognised lines:

* ``sshd``: Failed password / Failed publickey / Invalid user / Accepted password|publickey
* ``useradd``: new user
* ``usermod`` / ``gpasswd``: user added to a privileged group (sudo, wheel, admin)
* ``sudo``: successful sudo session open for root (treated as privilege use)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from ..models import (ACCOUNT_CREATED, GROUP_ADD, LOGIN_FAILED, LOGIN_SUCCESS, SRC_AUTH, Event,
                      ParseStats)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_./-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_./-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$")

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAILED_RE = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?:(?P<invalid>invalid user) )?(?P<user>\S+) from " + IP + r" port \d+")
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S*) from " + IP + r"(?: port \d+)?")
ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from " + IP + r" port \d+")
USERADD_RE = re.compile(r"^new user: name=(?P<user>[^,\s]+)")
GROUP_RE = re.compile(
    r"^(?:add '(?P<u1>[^']+)' to group '(?P<g1>[^']+)'|"
    r"user '?(?P<u2>[^'\s]+)'? added to group '?(?P<g2>[^'\s]+)'?)")
SUDO_USERADD_RE = re.compile(r"^\s*(?P<actor>\S+) : .*COMMAND=(?P<cmd>.*)$")

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}


def _parse_ts(match: "re.Match[str]", year: int, state: dict) -> Optional[datetime]:
    if "mon" in match.groupdict() and match.groupdict().get("mon"):
        mon = MONTHS.get(match.group("mon"))
        if not mon:
            return None
        # Year rollover: syslog has no year. If the month goes backwards we crossed New Year.
        last_mon = state.get("last_mon")
        if last_mon is not None and mon < last_mon - 6:
            state["year"] = state.get("year", year) + 1
        state["last_mon"] = mon
        yr = state.get("year", year)
        try:
            return datetime.strptime("{} {} {} {}".format(yr, mon, match.group("day"), match.group("time")),
                                     "%Y %m %d %H:%M:%S")
        except ValueError:
            return None
    ts = match.group("ts").replace("T", " ")
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_line(line: str, year: int, state: Optional[dict] = None) -> Tuple[str, Optional[Event]]:
    """Parse a single line.

    Returns ``("event", Event)``, ``("ignored", None)`` or ``("malformed", None)``.
    """
    state = state if state is not None else {}
    line = line.rstrip("\r\n")
    m = SYSLOG_RE.match(line) or ISO_RE.match(line)
    if not m:
        return "malformed", None
    ts = _parse_ts(m, year, state)
    if ts is None:
        return "malformed", None
    host, proc, msg = m.group("host"), m.group("proc"), m.group("msg")

    def ev(kind, **kw):
        extra = kw.pop("extra", {})
        return Event(ts=ts, source=SRC_AUTH, kind=kind, host=host, raw=line, extra=extra, **kw)

    if proc.startswith("sshd"):
        fm = FAILED_RE.match(msg)
        if fm:
            return "event", ev(LOGIN_FAILED, user=fm.group("user"), src_ip=fm.group("ip"),
                               extra={"method": fm.group("method"), "invalid_user": bool(fm.group("invalid")),
                                      "service": "ssh"})
        am = ACCEPTED_RE.match(msg)
        if am:
            return "event", ev(LOGIN_SUCCESS, user=am.group("user"), src_ip=am.group("ip"),
                               extra={"method": am.group("method"), "service": "ssh", "logon_type": "ssh"})
        im = INVALID_RE.match(msg)
        if im:
            # "Invalid user X from IP" always accompanies a failed attempt for a non-existent account.
            # The paired "Failed password for invalid user" line is what we count, so skip this
            # to avoid double counting.
            return "ignored", None
        return "ignored", None
    if proc == "useradd":
        um = USERADD_RE.match(msg)
        if um:
            return "event", ev(ACCOUNT_CREATED, user=um.group("user"), extra={"actor": state.get("last_sudo_actor", "")})
        return "ignored", None
    if proc in ("usermod", "gpasswd", "adduser"):
        gm = GROUP_RE.match(msg)
        if gm:
            user = gm.group("u1") or gm.group("u2")
            group = gm.group("g1") or gm.group("g2")
            return "event", ev(GROUP_ADD, user=user, extra={"group": group, "privileged": group in PRIVILEGED_GROUPS,
                                                           "actor": state.get("last_sudo_actor", "")})
        return "ignored", None
    if proc == "sudo":
        sm = SUDO_USERADD_RE.match(msg)
        if sm:
            state["last_sudo_actor"] = sm.group("actor")
        return "ignored", None
    return "ignored", None


def parse_auth_log(lines: Iterable[str], path: str = "<memory>", year: Optional[int] = None) -> Tuple[List[Event], ParseStats]:
    """Parse an iterable of auth.log lines into events (plus per-file statistics).

    ``year`` supplies the missing year for syslog timestamps (defaults to the current year).
    Blank lines and ``#`` comment lines (used to label synthetic data) are ignored.
    """
    year = year or datetime.now().year
    stats = ParseStats(path=path, source=SRC_AUTH)
    state: dict = {}
    events: List[Event] = []
    for line in lines:
        stats.lines += 1
        if not line.strip() or line.lstrip().startswith("#"):
            stats.ignored += 1
            continue
        kind, event = parse_line(line, year, state)
        if kind == "event" and event is not None:
            events.append(event)
            stats.parsed += 1
        elif kind == "ignored":
            stats.ignored += 1
        else:
            stats.malformed += 1
    return events, stats
