"""Parser for nginx / Apache *combined* access logs.

Format::

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Lines in the common format (no referer/user-agent) are accepted too; the user agent is then empty.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, List, Optional, Tuple
from urllib.parse import unquote

from ..models import HTTP_REQUEST, SRC_WEB, Event, ParseStats

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
REQ_RE = re.compile(r"^(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")
TIME_FMT = "%d/%b/%Y:%H:%M:%S"


def parse_line(line: str, host: str = "") -> Tuple[str, Optional[Event]]:
    line = line.rstrip("\r\n")
    m = LINE_RE.match(line)
    if not m:
        return "malformed", None
    try:
        ts = datetime.strptime(m.group("time").split(" ")[0], TIME_FMT)  # offset dropped: wall-clock time
    except ValueError:
        return "malformed", None
    request = m.group("request")
    rm = REQ_RE.match(request)
    if rm:
        method, path = rm.group("method"), rm.group("path")
    else:  # e.g. binary garbage or "-" sent by scanners; keep the request for pattern rules
        method, path = "", request
    ua = m.group("ua") or ""
    user = m.group("user")
    return "event", Event(
        ts=ts, source=SRC_WEB, kind=HTTP_REQUEST, host=host,
        user="" if user == "-" else user, src_ip=m.group("ip"), raw=line,
        extra={"method": method, "path": path, "decoded_path": unquote(unquote(path)),
               "status": int(m.group("status")), "bytes": 0 if m.group("bytes") == "-" else int(m.group("bytes")),
               "referer": "" if m.group("referer") in (None, "-") else m.group("referer"), "user_agent": "" if ua == "-" else ua})


def parse_web_access(lines: Iterable[str], path: str = "<memory>", host: str = "") -> Tuple[List[Event], ParseStats]:
    stats = ParseStats(path=path, source=SRC_WEB)
    events: List[Event] = []
    for line in lines:
        stats.lines += 1
        if not line.strip() or line.lstrip().startswith("#"):
            stats.ignored += 1
            continue
        status, event = parse_line(line, host=host)
        if status == "event" and event is not None:
            events.append(event)
            stats.parsed += 1
        else:
            stats.malformed += 1
    return events, stats
