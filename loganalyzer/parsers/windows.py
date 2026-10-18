"""Parser for Windows Security event log exports (CSV or JSON).

Supported event IDs (the ones a first-line analyst meets most often):

====  =====================================================
4624  An account was successfully logged on
4625  An account failed to log on
4672  Special privileges assigned to new logon
4688  A new process has been created
4720  A user account was created
4732  A member was added to a security-enabled local group
====  =====================================================

Exports differ between tools (``Get-WinEvent | Export-Csv``, Event Viewer "Save
as CSV", SIEM exports), so column/field names are matched through alias lists
and case-insensitively. Accepted JSON shapes: a list of objects, an object with
an ``events`` (or ``Events``/``records``) list, or newline-delimited JSON.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models import (ACCOUNT_CREATED, GROUP_ADD, LOGIN_FAILED, LOGIN_SUCCESS, PRIVILEGE_ASSIGNED,
                      PROCESS_CREATED, SRC_WINDOWS, Event, ParseStats)

ALIASES = {
    "time": ["timecreated", "time", "timestamp", "timegenerated", "datetime", "date and time", "@timestamp"],
    "event_id": ["eventid", "id", "event id", "event_id"],
    "host": ["computer", "machinename", "hostname", "host", "computername"],
    "target_user": ["targetusername", "target user name", "target_user", "accountname", "account name"],
    "target_domain": ["targetdomainname", "target domain name", "target_domain", "accountdomain"],
    "subject_user": ["subjectusername", "subject user name", "subject_user", "creatoruser"],
    "logon_type": ["logontype", "logon type", "logon_type"],
    "ip": ["ipaddress", "ip address", "sourcenetworkaddress", "source network address", "src_ip", "sourceip", "ip"],
    "workstation": ["workstationname", "workstation name", "workstation"],
    "status": ["status"],
    "sub_status": ["substatus", "sub status", "sub_status"],
    "process": ["newprocessname", "new process name", "process", "processname"],
    "command_line": ["commandline", "command line", "processcommandline", "command_line"],
    "parent_process": ["parentprocessname", "parent process name", "creatorprocessname", "parent_process"],
    "privileges": ["privilegelist", "privilege list", "privileges"],
    "group": ["targetgroup", "group", "groupname", "group name"],
}

SUPPORTED_IDS = {4624, 4625, 4672, 4688, 4720, 4732}
# Logon types that represent a person/remote actor (not services or batch jobs).
INTERACTIVE_TYPES = {"2", "3", "7", "10", "11"}
TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
              "%d/%m/%Y %H:%M:%S")
_MS_DATE = re.compile(r"/Date\((\d+)\)/")
_NULL_VALUES = {"", "-", "::1", "127.0.0.1", "null", "none"}


def _build_lookup(record: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k).strip().lower(): v for k, v in record.items()}


def _get(lookup: Dict[str, Any], key: str) -> str:
    for alias in ALIASES[key]:
        if alias in lookup and lookup[alias] is not None:
            return str(lookup[alias]).strip()
    return ""


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse the timestamp styles seen in Windows exports; offsets are dropped (wall-clock time)."""
    if not value:
        return None
    value = value.strip()
    m = _MS_DATE.search(value)
    if m:  # Get-WinEvent | ConvertTo-Json on Windows PowerShell 5.1
        return datetime.fromtimestamp(int(m.group(1)) / 1000.0, timezone.utc).replace(tzinfo=None)
    v = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", value)   # drop UTC offset / Z
    v = re.sub(r"\.\d+$", "", v)                       # drop fractional seconds
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def _clean_ip(ip: str) -> str:
    ip = ip.strip()
    if ip.lower() in _NULL_VALUES:
        return ""
    return ip.replace("::ffff:", "")


def record_to_event(record: Dict[str, Any], raw: str) -> Tuple[str, Optional[Event]]:
    """Convert a dict-like record to an Event. Returns (status, event)."""
    lk = _build_lookup(record)
    ts = parse_timestamp(_get(lk, "time"))
    eid_text = _get(lk, "event_id")
    try:
        eid = int(float(eid_text))
    except ValueError:
        return "malformed", None
    if ts is None:
        return "malformed", None
    if eid not in SUPPORTED_IDS:
        return "ignored", None

    host = _get(lk, "host")
    target_user = _get(lk, "target_user")
    subject_user = _get(lk, "subject_user")
    domain = _get(lk, "target_domain")
    ip = _clean_ip(_get(lk, "ip"))
    extra: Dict[str, Any] = {"event_id": eid, "domain": domain}

    def make(kind, user, **more):
        extra.update(more)
        return Event(ts=ts, source=SRC_WINDOWS, kind=kind, host=host, user=user, src_ip=ip, raw=raw, extra=extra)

    if eid in (4624, 4625):
        ltype = _get(lk, "logon_type")
        extra.update({"logon_type": ltype, "workstation": _get(lk, "workstation"), "service": "windows"})
        if eid == 4625:
            extra.update({"status": _get(lk, "status"), "sub_status": _get(lk, "sub_status")})
            return "event", make(LOGIN_FAILED, target_user)
        return "event", make(LOGIN_SUCCESS, target_user)
    if eid == 4672:
        return "event", make(PRIVILEGE_ASSIGNED, subject_user or target_user, privileges=_get(lk, "privileges"))
    if eid == 4688:
        return "event", make(PROCESS_CREATED, subject_user or target_user, process=_get(lk, "process"),
                             command_line=_get(lk, "command_line"), parent_process=_get(lk, "parent_process"))
    if eid == 4720:
        return "event", make(ACCOUNT_CREATED, target_user, actor=subject_user)
    # 4732
    group = _get(lk, "group")
    return "event", make(GROUP_ADD, target_user, group=group, actor=subject_user,
                         privileged=group.lower() in ("administrators", "domain admins", "remote desktop users"))


def _records_from_json(text: str) -> List[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for ln in text.splitlines():  # NDJSON fallback
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                obj = None
            records.append(obj if isinstance(obj, dict) else {"__malformed__": ln})
        return records
    if isinstance(data, dict):
        for key in ("events", "Events", "records", "Records", "value"):
            if isinstance(data.get(key), list):
                return [r if isinstance(r, dict) else {"__malformed__": str(r)} for r in data[key]]
        return [data]
    if isinstance(data, list):
        return [r if isinstance(r, dict) else {"__malformed__": str(r)} for r in data]
    return [{"__malformed__": text[:80]}]


def parse_windows_events(text: str, path: str = "<memory>", fmt: Optional[str] = None) -> Tuple[List[Event], ParseStats]:
    """Parse the full text of a Windows Security export.

    ``fmt`` is ``"csv"`` or ``"json"``; if omitted it is guessed from the path extension or content.
    """
    stats = ParseStats(path=path, source=SRC_WINDOWS)
    if fmt is None:
        lower = path.lower()
        if lower.endswith(".json") or lower.endswith(".jsonl") or lower.endswith(".ndjson"):
            fmt = "json"
        elif lower.endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "json" if text.lstrip()[:1] in ("{", "[") else "csv"
    events: List[Event] = []

    if fmt == "json":
        records = _records_from_json(text)
        raws = [json.dumps(r, sort_keys=True) for r in records]
    else:
        body = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        stats.ignored += len(text.splitlines()) - len(body)
        reader = csv.DictReader(io.StringIO("\n".join(body)))
        records = []
        raws = []
        for row in reader:
            if None in row:  # more fields than header
                row = {k: v for k, v in row.items() if k is not None}
                row["__malformed__"] = "extra fields"
            records.append(row)
            raws.append(",".join("" if v is None else str(v) for v in row.values()))
    stats.lines = len(records) + stats.ignored
    for record, raw in zip(records, raws):
        if "__malformed__" in record:
            stats.malformed += 1
            continue
        status, event = record_to_event(record, raw)
        if status == "event" and event is not None:
            events.append(event)
            stats.parsed += 1
        elif status == "ignored":
            stats.ignored += 1
        else:
            stats.malformed += 1
    return events, stats
