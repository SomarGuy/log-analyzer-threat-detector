"""Detection engine: runs every enabled rule, de-duplicates, correlates alerts into incidents."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .alerts import TACTIC_ORDER, Alert, Incident, iso, max_severity
from .detectors import DETECTORS
from .models import SEVERITY_ORDER, Event, ParseStats
from .rules import Rule

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7")]
HOST_LINK_MINUTES = 30   # IP-less alerts (e.g. account creation) join an incident on the same host within this long


@dataclass
class AnalysisResult:
    alerts: List[Alert]
    incidents: List[Incident]
    rules: List[Rule]
    events_total: int
    parse_stats: List[ParseStats] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


def run_rules(events: Sequence[Event], rules: Iterable[Rule], ignore_ips: Iterable[str] = ()) -> List[Alert]:
    ignored = set(ignore_ips)
    evs = sorted((e for e in events if e.src_ip not in ignored), key=lambda e: e.ts)
    alerts: List[Alert] = []
    for rule in rules:
        if not rule.enabled:
            continue
        subset = [e for e in evs if e.source in rule.sources]
        alerts.extend(DETECTORS[rule.type](rule, subset))
    alerts.sort(key=lambda a: (a.first_seen, -SEVERITY_ORDER[a.severity], a.rule_id))
    for n, alert in enumerate(alerts, 1):
        alert.id = "ALR-{:03d}".format(n)
    return alerts


# --------------------------------------------------------------------------- correlation


def _tactics(alerts: Sequence[Alert]) -> List[str]:
    found = {m["tactic"] for a in alerts for m in a.mitre}
    return sorted(found, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)


def correlate(alerts: List[Alert]) -> List[Incident]:
    """Group alerts into incidents.

    1. Alerts that share a source IP belong together (a single actor, possibly seen in several logs).
    2. Alerts with no IP (account creation, process execution) join the incident on the same host
       whose activity ended at most ``HOST_LINK_MINUTES`` before them.
    Single-alert groups below ``critical`` severity are left as plain alerts.
    """
    parent: Dict[int, int] = {i: i for i in range(len(alerts))}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    by_ip: Dict[str, int] = {}
    for i, a in enumerate(alerts):
        for ip in a.source_ips:
            if ip in by_ip:
                parent[find(i)] = find(by_ip[ip])
            else:
                by_ip[ip] = i

    groups: Dict[int, List[int]] = defaultdict(list)
    for i, a in enumerate(alerts):
        if a.source_ips:
            groups[find(i)].append(i)

    def span(idx: List[int]):
        return (min(alerts[i].first_seen for i in idx), max(alerts[i].last_seen for i in idx),
                {h for i in idx for h in alerts[i].hosts})

    link = timedelta(minutes=HOST_LINK_MINUTES)
    for i, a in enumerate(alerts):           # alerts are already sorted by first_seen
        if a.source_ips:
            continue
        candidates = []
        for root, idx in groups.items():
            first, last, hosts = span(idx)
            if set(a.hosts) & hosts and first <= a.first_seen <= last + link:
                best = max(SEVERITY_ORDER[alerts[j].severity] for j in idx)
                candidates.append((best, last, root))
        if candidates:
            candidates.sort(reverse=True)
            groups[candidates[0][2]].append(i)
        else:
            groups[find(i)].append(i)   # standalone

    incidents: List[Incident] = []
    for idx in groups.values():
        members = sorted((alerts[i] for i in idx), key=lambda a: a.first_seen)
        sev = max_severity(a.severity for a in members)
        if len(members) < 2 and SEVERITY_ORDER[sev] < SEVERITY_ORDER["critical"]:
            continue
        first, last, hosts = span(idx)
        ips = sorted({ip for a in members for ip in a.source_ips})
        tactics = _tactics(members)
        who = ", ".join(ips[:3]) if ips else "host " + ", ".join(sorted(hosts)[:2])
        narrative = ["{} {} ({}, {} event{})".format(a.first_seen.strftime("%a %H:%M"), a.title, a.rule_id, a.count,
                                                     "" if a.count == 1 else "s") for a in members]
        incidents.append(Incident(id="", title="{}: {}".format(who, " > ".join(tactics)), severity=sev,
                                  first_seen=first, last_seen=last, source_ips=ips, hosts=sorted(hosts),
                                  alert_ids=[a.id for a in members], tactics=tactics, narrative=narrative))
    incidents.sort(key=lambda inc: (-SEVERITY_ORDER[inc.severity], inc.first_seen))
    for n, inc in enumerate(incidents, 1):
        inc.id = "INC-{:02d}".format(n)
    by_id = {a.id: a for a in alerts}
    for inc in incidents:
        for aid in inc.alert_ids:
            by_id[aid].incident_id = inc.id
    return incidents


# --------------------------------------------------------------------------- statistics


def volume_by_hour(events: Sequence[Event]) -> List[Dict[str, Any]]:
    buckets: Dict[str, Counter] = defaultdict(Counter)
    for e in events:
        buckets[e.ts.strftime("%Y-%m-%dT%H:00:00")][e.source] += 1
    return [{"hour": h, **dict(c), "total": sum(c.values())} for h, c in sorted(buckets.items())]


def is_internal(ip: str) -> bool:
    """True for RFC 1918 / loopback / link-local addresses. (RFC 5737 documentation ranges count as external here.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS if net.version == addr.version)


def top_attackers(alerts: Sequence[Alert], limit: int = 10) -> List[Dict[str, Any]]:
    table: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        for ip in a.source_ips:
            row = table.setdefault(ip, {"ip": ip, "alerts": 0, "events": 0, "max_severity": "low",
                                        "rules": set(), "first_seen": a.first_seen, "last_seen": a.last_seen})
            row["alerts"] += 1
            row["events"] += a.count
            row["max_severity"] = max_severity([row["max_severity"], a.severity])
            row["rules"].add(a.rule_id)
            row["first_seen"] = min(row["first_seen"], a.first_seen)
            row["last_seen"] = max(row["last_seen"], a.last_seen)
    rows = sorted(table.values(), key=lambda r: (-SEVERITY_ORDER[r["max_severity"]], -r["alerts"], -r["events"], r["ip"]))
    return [{**r, "internal": is_internal(r["ip"]), "rules": sorted(r["rules"]), "first_seen": iso(r["first_seen"]), "last_seen": iso(r["last_seen"])}
            for r in rows[:limit]]


def mitre_summary(alerts: Sequence[Alert]) -> List[Dict[str, Any]]:
    table: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        for m in a.mitre:
            row = table.setdefault(m["id"], {**m, "alerts": 0, "max_severity": "low", "rules": set()})
            row["alerts"] += 1
            row["max_severity"] = max_severity([row["max_severity"], a.severity])
            row["rules"].add(a.rule_id)
    return [{**r, "rules": sorted(r["rules"])} for r in sorted(
        table.values(), key=lambda r: (TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99, r["id"]))]


def analyze(events: Sequence[Event], rules: Sequence[Rule], parse_stats: Optional[Sequence[ParseStats]] = None,
            ignore_ips: Iterable[str] = ()) -> AnalysisResult:
    alerts = run_rules(events, rules, ignore_ips)
    incidents = correlate(alerts)
    evs = sorted(events, key=lambda e: e.ts)
    stats = {
        "events_total": len(evs),
        "events_by_source": dict(Counter(e.source for e in evs)),
        "time_range": [iso(evs[0].ts), iso(evs[-1].ts)] if evs else [],
        "volume_by_hour": volume_by_hour(evs),
        "unique_source_ips": len({e.src_ip for e in evs if e.src_ip}),
    }
    return AnalysisResult(alerts=alerts, incidents=incidents, rules=list(rules), events_total=len(evs),
                          parse_stats=list(parse_stats or []), stats=stats)
