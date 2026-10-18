"""Alert and incident objects, plus helpers shared by the detectors."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Sequence

from .models import SEVERITY_ORDER, Event
from .rules import Rule

TIME_FMT = "%Y-%m-%dT%H:%M:%S"
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
                "Command and Control", "Exfiltration", "Impact"]


def iso(ts: datetime) -> str:
    return ts.strftime(TIME_FMT)


def sample_events(events: Sequence[Event], limit: int) -> List[Event]:
    """Pick up to ``limit`` events spread evenly across the list, always keeping the first and last."""
    if len(events) <= limit:
        return list(events)
    if limit < 2:
        return [events[0]]
    step = (len(events) - 1) / float(limit - 1)
    idx = sorted({int(round(i * step)) for i in range(limit)})
    return [events[i] for i in idx]


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    count: int
    source_ips: List[str]
    users: List[str]
    hosts: List[str]
    log_sources: List[str]
    description: str
    mitre: List[Dict[str, str]]
    response: List[str]
    timeline: List[Dict[str, str]]
    evidence: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    id: str = ""
    incident_id: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "first_seen": iso(self.first_seen), "last_seen": iso(self.last_seen),
            "duration_seconds": int((self.last_seen - self.first_seen).total_seconds()),
            "count": self.count, "source_ips": self.source_ips, "users": self.users, "hosts": self.hosts,
            "log_sources": self.log_sources, "description": self.description, "mitre": self.mitre,
            "recommended_response": self.response, "timeline": self.timeline, "evidence": self.evidence,
            "details": self.details, "incident_id": self.incident_id,
        }


def _uniq(values) -> List[str]:
    seen, out = set(), []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def make_alert(rule: Rule, events: Sequence[Event], severity: str | None = None, title: str | None = None,
               details: Dict[str, Any] | None = None, description: str | None = None,
               count: int | None = None) -> Alert:
    """Build an Alert from the matching events (which must be non-empty and time-ordered)."""
    events = sorted(events, key=lambda e: e.ts)
    sampled = sample_events(events, 12)
    timeline = [{"ts": iso(e.ts), "source": e.source, "event": e.summary()} for e in sampled]
    ev_lines = sample_events(events, 5)
    return Alert(
        rule_id=rule.id, title=title or rule.name, severity=severity or rule.severity,
        first_seen=events[0].ts, last_seen=events[-1].ts, count=count if count is not None else len(events),
        source_ips=_uniq(e.src_ip for e in events), users=_uniq(e.user for e in events)[:25],
        hosts=_uniq(e.host for e in events), log_sources=_uniq(e.source for e in events),
        description=description or rule.description, mitre=rule.mitre, response=rule.response,
        timeline=timeline, evidence=[e.raw[:400] for e in ev_lines], details=details or {})


def max_severity(severities) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER[s])


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    source_ips: List[str]
    hosts: List[str]
    alert_ids: List[str]
    tactics: List[str]
    narrative: List[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "first_seen": iso(self.first_seen), "last_seen": iso(self.last_seen),
                "source_ips": self.source_ips, "hosts": self.hosts, "alert_ids": self.alert_ids,
                "tactics": self.tactics, "narrative": self.narrative}
