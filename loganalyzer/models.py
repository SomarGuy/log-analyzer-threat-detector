"""Normalised data model shared by all parsers and detectors."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

# Normalised event types produced by the parsers.
LOGIN_FAILED = "login_failed"
LOGIN_SUCCESS = "login_success"
PRIVILEGE_ASSIGNED = "privilege_assigned"   # Windows 4672 / sudo
ACCOUNT_CREATED = "account_created"         # Windows 4720 / useradd
GROUP_ADD = "group_add"                     # Windows 4732 / usermod -aG sudo
PROCESS_CREATED = "process_created"         # Windows 4688
HTTP_REQUEST = "http_request"

# Log sources.
SRC_AUTH = "auth"
SRC_WINDOWS = "windows"
SRC_WEB = "web"

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Event:
    """One normalised log record.

    Timestamps are naive wall-clock times exactly as written in the log; no
    timezone conversion is performed (see README, Limitations).
    """

    ts: datetime
    source: str                  # SRC_AUTH | SRC_WINDOWS | SRC_WEB
    kind: str                    # one of the constants above
    host: str = ""
    user: str = ""
    src_ip: str = ""
    raw: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """Short human-readable one-liner used in alert timelines."""
        if self.kind == HTTP_REQUEST:
            return "{} {} -> {}".format(self.extra.get("method", ""), self.extra.get("path", ""), self.extra.get("status", ""))
        if self.kind == LOGIN_FAILED:
            return "failed login user={} from {}".format(self.user or "?", self.src_ip or "?")
        if self.kind == LOGIN_SUCCESS:
            return "successful login user={} from {}".format(self.user or "?", self.src_ip or "?")
        if self.kind == ACCOUNT_CREATED:
            return "account created: {} (by {})".format(self.user, self.extra.get("actor", "?"))
        if self.kind == GROUP_ADD:
            return "{} added to group {}".format(self.user, self.extra.get("group", "?"))
        if self.kind == PRIVILEGE_ASSIGNED:
            return "special privileges assigned to {}".format(self.user)
        if self.kind == PROCESS_CREATED:
            return "process: {}".format((self.extra.get("command_line") or self.extra.get("process") or "")[:140])
        return self.kind


@dataclass
class ParseStats:
    """Counts reported per input file so silent parse failures are visible."""

    path: str
    source: str
    lines: int = 0
    parsed: int = 0       # lines/records that became an Event
    ignored: int = 0      # understood but irrelevant (e.g. cron lines, comments)
    malformed: int = 0    # could not be understood

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "source": self.source, "lines": self.lines,
            "parsed": self.parsed, "ignored": self.ignored, "malformed": self.malformed,
        }
