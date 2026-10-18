"""Detector implementations. One function per rule ``type`` in the rule file.

Every detector has the signature ``detector(rule, events) -> list[Alert]`` where
``events`` is already filtered to the rule's log sources and sorted by time.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Sequence, Tuple

from .alerts import Alert, make_alert
from .models import (ACCOUNT_CREATED, GROUP_ADD, HTTP_REQUEST, LOGIN_FAILED, LOGIN_SUCCESS,
                     PRIVILEGE_ASSIGNED, PROCESS_CREATED, SEVERITY_ORDER, Event)
from .rules import Rule

# --------------------------------------------------------------------------- helpers


def sliding_episodes(times: Sequence[datetime], threshold: int, window_seconds: int) -> List[Tuple[int, int]]:
    """Find bursts in a sorted list of timestamps.

    A burst is any run where ``threshold`` or more events fall within
    ``window_seconds`` of each other. Overlapping windows are merged so one
    sustained attack yields one episode. Returns inclusive ``(start, end)``
    index pairs into ``times``.
    """
    ranges: List[Tuple[int, int]] = []
    left = 0
    for i in range(len(times)):
        while (times[i] - times[left]).total_seconds() > window_seconds:
            left += 1
        if i - left + 1 >= threshold:
            ranges.append((left, i))
    merged: List[List[int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def cluster_by_gap(events: Sequence[Event], gap_seconds: int) -> List[List[Event]]:
    """Split time-sorted events into sessions separated by quiet gaps longer than ``gap_seconds``."""
    clusters: List[List[Event]] = []
    for e in events:
        if clusters and (e.ts - clusters[-1][-1].ts).total_seconds() <= gap_seconds:
            clusters[-1].append(e)
        else:
            clusters.append([e])
    return clusters


def _group(events: Iterable[Event], key: Callable[[Event], tuple]) -> Dict[tuple, List[Event]]:
    groups: Dict[tuple, List[Event]] = defaultdict(list)
    for e in events:
        groups[key(e)].append(e)
    return groups


def _compile(patterns: Sequence[str]) -> List["re.Pattern[str]"]:
    return [re.compile(p) for p in patterns]


def _bump(severity: str, other: str) -> str:
    return other if SEVERITY_ORDER[other] > SEVERITY_ORDER[severity] else severity


# --------------------------------------------------------------------------- authentication


def login_failure_burst(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    alerts: List[Alert] = []
    failed = [e for e in events if e.kind == LOGIN_FAILED and e.src_ip]
    for (ip, source), evs in _group(failed, lambda e: (e.src_ip, e.source)).items():
        for start, end in sliding_episodes([e.ts for e in evs], p["threshold"], p["window_seconds"]):
            burst = evs[start:end + 1]
            per_user = Counter(e.user for e in burst)
            avg = len(burst) / float(len(per_user))
            if avg <= p.get("min_avg_attempts_per_user", 0):
                continue  # many accounts, few tries each: that is password spraying (AUTH-002)
            minutes = max((burst[-1].ts - burst[0].ts).total_seconds() / 60.0, 1 / 60.0)
            alerts.append(make_alert(rule, burst, details={
                "failed_attempts": len(burst), "distinct_accounts": len(per_user),
                "attempts_per_minute": round(len(burst) / minutes, 1),
                "top_accounts": [{"user": u, "attempts": n} for u, n in per_user.most_common(5)],
                "log_source": source}))
    return alerts


def password_spray(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    alerts: List[Alert] = []
    failed = [e for e in events if e.kind == LOGIN_FAILED and e.src_ip and e.user]
    for (ip, source), evs in _group(failed, lambda e: (e.src_ip, e.source)).items():
        counts: Counter = Counter()
        left = 0
        ranges: List[List[int]] = []
        for i, e in enumerate(evs):
            counts[e.user] += 1
            while (e.ts - evs[left].ts).total_seconds() > p["window_seconds"]:
                counts[evs[left].user] -= 1
                if counts[evs[left].user] == 0:
                    del counts[evs[left].user]
                left += 1
            if len(counts) >= p["min_distinct_users"]:
                if ranges and left <= ranges[-1][1]:
                    ranges[-1][1] = i
                else:
                    ranges.append([left, i])
        for start, end in ranges:
            burst = evs[start:end + 1]
            users = Counter(e.user for e in burst)
            avg = len(burst) / float(len(users))
            # judged over the whole episode, so the ramp-up of a loud brute force is not mistaken for a spray
            if avg > p.get("max_attempts_per_user", 3):
                continue
            alerts.append(make_alert(rule, burst, details={
                "distinct_accounts": len(users), "failed_attempts": len(burst),
                "avg_attempts_per_account": round(avg, 2), "log_source": source}))
    return alerts


def success_after_failures(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    window = timedelta(seconds=p["window_seconds"])
    alerts: List[Alert] = []
    relevant = [e for e in events if e.kind in (LOGIN_FAILED, LOGIN_SUCCESS) and e.src_ip]
    for (ip, source), evs in _group(relevant, lambda e: (e.src_ip, e.source)).items():
        fails = [e for e in evs if e.kind == LOGIN_FAILED]
        wins = [e for e in evs if e.kind == LOGIN_SUCCESS]
        qualifying: List[Tuple[Event, List[Event]]] = []
        for s in wins:
            before = [f for f in fails if s.ts - window <= f.ts <= s.ts]
            if len(before) >= p["threshold"]:
                qualifying.append((s, before))
        # merge qualifying successes that follow each other into one alert
        clusters: List[List[Tuple[Event, List[Event]]]] = []
        for item in qualifying:
            if clusters and item[0].ts - clusters[-1][-1][0].ts <= window:
                clusters[-1].append(item)
            else:
                clusters.append([item])
        for cluster in clusters:
            successes = [s for s, _ in cluster]
            first_before = cluster[0][1]
            evs_all = list(first_before) + successes
            alerts.append(make_alert(rule, evs_all, details={
                "failures_before_success": len(first_before),
                "accounts_logged_in": sorted({s.user for s in successes}),
                "first_success": successes[0].ts.strftime("%Y-%m-%dT%H:%M:%S"),
                "log_source": source}, count=len(evs_all)))
    return alerts


# --------------------------------------------------------------------------- account changes


def account_created(rule: Rule, events: List[Event]) -> List[Alert]:
    alerts = []
    for e in events:
        if e.kind == ACCOUNT_CREATED:
            alerts.append(make_alert(rule, [e], title="New account created: {}".format(e.user),
                                     details={"new_account": e.user, "created_by": e.extra.get("actor", "")}))
    return alerts


def account_created_privileged(rule: Rule, events: List[Event]) -> List[Alert]:
    window = timedelta(seconds=rule.params["window_seconds"])
    alerts = []
    created = [e for e in events if e.kind == ACCOUNT_CREATED]
    privs = [e for e in events if (e.kind == GROUP_ADD and e.extra.get("privileged")) or e.kind == PRIVILEGE_ASSIGNED]
    for c in created:
        hits = [x for x in privs if x.user == c.user and c.ts <= x.ts <= c.ts + window]
        if hits:
            how = sorted({x.extra.get("group") or "special privileges (4672)" for x in hits})
            alerts.append(make_alert(
                rule, [c] + hits, title="New account '{}' was given administrative rights".format(c.user),
                details={"new_account": c.user, "created_by": c.extra.get("actor", ""), "privilege_via": how,
                         "minutes_to_privilege": round((hits[0].ts - c.ts).total_seconds() / 60.0, 1)}))
    return alerts


def off_hours_login(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    start, end = p["business_start_hour"], p["business_end_hour"]
    workdays = set(p.get("workdays", [0, 1, 2, 3, 4]))
    types = set(p.get("logon_types", []))
    excluded = set(p.get("exclude_users", []))
    priv = _group((e for e in events if e.kind == PRIVILEGE_ASSIGNED), lambda e: (e.user,))

    def off_hours(ts: datetime) -> bool:
        return ts.weekday() not in workdays or ts.hour < start or ts.hour >= end

    def is_priv(login: Event) -> bool:
        return any(abs((x.ts - login.ts).total_seconds()) <= 60 for x in priv.get((login.user,), []))

    hits = [e for e in events if e.kind == LOGIN_SUCCESS and e.user and e.user not in excluded
            and not e.user.endswith("$") and off_hours(e.ts)
            and (not types or not e.extra.get("logon_type") or e.extra.get("logon_type") in types)]
    alerts = []
    for (user, ip, host), evs in _group(hits, lambda e: (e.user, e.src_ip, e.host)).items():
        privileged = any(is_priv(e) for e in evs)
        sev = p.get("privileged_severity", "high") if privileged else rule.severity
        alerts.append(make_alert(
            rule, evs, severity=_bump(rule.severity, sev),
            title="Off-hours login: {}{}".format(user, " (privileged)" if privileged else ""),
            details={"user": user, "privileged_session": privileged,
                     "login_times": [e.ts.strftime("%a %Y-%m-%d %H:%M") for e in evs[:5]],
                     "business_hours": "{:02d}:00-{:02d}:00 on weekdays".format(start, end)}))
    return alerts


# --------------------------------------------------------------------------- web


def http_status_burst(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    statuses = set(p["statuses"])
    hits = [e for e in events if e.kind == HTTP_REQUEST and e.extra.get("status") in statuses and e.src_ip]
    alerts = []
    for (ip,), evs in _group(hits, lambda e: (e.src_ip,)).items():
        for start, end in sliding_episodes([e.ts for e in evs], p["threshold"], p["window_seconds"]):
            burst = evs[start:end + 1]
            paths = Counter(e.extra.get("path") for e in burst)
            uas = sorted({e.extra.get("user_agent") or "(empty)" for e in burst})
            minutes = max((burst[-1].ts - burst[0].ts).total_seconds() / 60.0, 1 / 60.0)
            alerts.append(make_alert(rule, burst, details={
                "requests": len(burst), "distinct_paths": len(paths), "status_codes": sorted(statuses),
                "requests_per_minute": round(len(burst) / minutes, 1), "user_agents": uas[:5],
                "sample_paths": [pth for pth, _ in paths.most_common(5)]}))
    return alerts


def http_pattern(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    patterns = _compile(p["patterns"])
    escalate = set(p.get("escalate_on_status", []))
    hits = []
    for e in events:
        if e.kind != HTTP_REQUEST or not e.src_ip:
            continue
        target = e.extra.get("decoded_path", e.extra.get("path", ""))
        if any(rx.search(target) for rx in patterns) or any(rx.search(e.extra.get("path", "")) for rx in patterns):
            hits.append(e)
    alerts = []
    for (ip,), evs in _group(hits, lambda e: (e.src_ip,)).items():
        measure = len({e.extra.get("path") for e in evs}) if p.get("distinct_paths") else len(evs)
        if measure < p.get("min_matches", 1):
            continue
        success = [e for e in evs if e.extra.get("status") in escalate]
        severity = rule.severity
        details = {"matching_requests": len(evs), "status_codes": dict(Counter(str(e.extra.get("status")) for e in evs)),
                   "sample_payloads": sorted({e.extra.get("decoded_path", "")[:160] for e in evs})[:5],
                   "user_agents": sorted({e.extra.get("user_agent") or "(empty)" for e in evs})[:3]}
        if success and p.get("escalated_severity"):
            severity = _bump(severity, p["escalated_severity"])
            details["possible_success"] = [
                "{} -> {} ({} bytes)".format(e.extra.get("path", "")[:120], e.extra.get("status"), e.extra.get("bytes"))
                for e in success[:5]]
        alerts.append(make_alert(rule, evs, severity=severity, details=details))
    return alerts


def http_user_agent(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    patterns = _compile(p["patterns"])
    hits = [e for e in events if e.kind == HTTP_REQUEST and e.src_ip
            and any(rx.search(e.extra.get("user_agent", "")) for rx in patterns)]
    alerts = []
    for (ip,), evs in _group(hits, lambda e: (e.src_ip,)).items():
        if len(evs) < p.get("min_requests", 1):
            continue
        uas = Counter(e.extra.get("user_agent") or "(empty)" for e in evs)
        alerts.append(make_alert(rule, evs, details={
            "requests": len(evs), "user_agents": [ua for ua, _ in uas.most_common(3)]}))
    return alerts


# --------------------------------------------------------------------------- processes


def process_match(rule: Rule, events: List[Event]) -> List[Alert]:
    p = rule.params
    patterns = _compile(p["patterns"])
    gap = p.get("window_seconds", 3600)
    hits = []
    for e in events:
        if e.kind != PROCESS_CREATED:
            continue
        text = e.extra.get("command_line") or e.extra.get("process") or ""
        if any(rx.search(text) for rx in patterns):
            hits.append(e)
    alerts = []
    for (host, user), evs in _group(hits, lambda e: (e.host, e.user)).items():
        for cluster in cluster_by_gap(evs, gap):
            if len(cluster) < p.get("min_matches", 1):
                continue
            alerts.append(make_alert(rule, cluster, details={
                "host": host, "account": user,
                "commands": [(c.extra.get("command_line") or c.extra.get("process") or "")[:200] for c in cluster[:5]],
                "parent_processes": sorted({c.extra.get("parent_process", "") for c in cluster if c.extra.get("parent_process")})}))
    return alerts


DETECTORS: Dict[str, Callable[[Rule, List[Event]], List[Alert]]] = {
    "login_failure_burst": login_failure_burst,
    "password_spray": password_spray,
    "success_after_failures": success_after_failures,
    "account_created": account_created,
    "account_created_privileged": account_created_privileged,
    "off_hours_login": off_hours_login,
    "http_status_burst": http_status_burst,
    "http_pattern": http_pattern,
    "http_user_agent": http_user_agent,
    "process_match": process_match,
}
