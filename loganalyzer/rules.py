"""Loading and validating the JSON detection rule file."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from .models import SEVERITY_ORDER

KNOWN_TYPES = {
    "login_failure_burst", "password_spray", "success_after_failures", "account_created",
    "account_created_privileged", "off_hours_login", "http_status_burst", "http_pattern",
    "http_user_agent", "process_match",
}
KNOWN_SOURCES = {"auth", "windows", "web"}
# Params that must be present (and positive) for each rule type.
REQUIRED_PARAMS = {
    "login_failure_burst": ["threshold", "window_seconds"],
    "password_spray": ["min_distinct_users", "window_seconds"],
    "success_after_failures": ["threshold", "window_seconds"],
    "account_created": [],
    "account_created_privileged": ["window_seconds"],
    "off_hours_login": ["business_start_hour", "business_end_hour"],
    "http_status_burst": ["threshold", "window_seconds", "statuses"],
    "http_pattern": ["patterns"],
    "http_user_agent": ["patterns"],
    "process_match": ["patterns"],
}
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "detection_rules.json"


class RuleError(ValueError):
    """Raised when the rule file is malformed. The message names the offending rule."""


@dataclass
class Rule:
    id: str
    name: str
    type: str
    severity: str
    description: str = ""
    sources: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    mitre: List[Dict[str, str]] = field(default_factory=list)
    response: List[str] = field(default_factory=list)
    enabled: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "type": self.type, "severity": self.severity,
                "description": self.description, "sources": self.sources, "params": self.params,
                "mitre": self.mitre, "response": self.response, "enabled": self.enabled}


def _validate(raw: Dict[str, Any], index: int) -> Rule:
    rid = raw.get("id") or "<rule #{}>".format(index)
    for key in ("id", "name", "type", "severity"):
        if not raw.get(key):
            raise RuleError("{}: missing required field '{}'".format(rid, key))
    if raw["type"] not in KNOWN_TYPES:
        raise RuleError("{}: unknown rule type '{}' (known: {})".format(rid, raw["type"], ", ".join(sorted(KNOWN_TYPES))))
    if raw["severity"] not in SEVERITY_ORDER:
        raise RuleError("{}: severity must be one of {}".format(rid, ", ".join(SEVERITY_ORDER)))
    sources = raw.get("sources") or []
    bad = [s for s in sources if s not in KNOWN_SOURCES]
    if not sources or bad:
        raise RuleError("{}: 'sources' must be a non-empty list drawn from {}".format(rid, sorted(KNOWN_SOURCES)))
    params = raw.get("params") or {}
    for p in REQUIRED_PARAMS[raw["type"]]:
        if p not in params:
            raise RuleError("{}: missing param '{}' for type '{}'".format(rid, p, raw["type"]))
    for p in ("threshold", "window_seconds", "min_distinct_users", "min_matches", "min_requests"):
        if p in params and (not isinstance(params[p], int) or params[p] <= 0):
            raise RuleError("{}: param '{}' must be a positive integer".format(rid, p))
    for p in ("patterns",):
        if p in params:
            if not isinstance(params[p], list) or not params[p]:
                raise RuleError("{}: 'patterns' must be a non-empty list of regular expressions".format(rid))
            for pat in params[p]:
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise RuleError("{}: invalid regex {!r}: {}".format(rid, pat, exc))
    for key in ("escalated_severity", "privileged_severity"):
        if key in params and params[key] not in SEVERITY_ORDER:
            raise RuleError("{}: '{}' must be a valid severity".format(rid, key))
    mitre = raw.get("mitre") or []
    for m in mitre:
        if not re.match(r"^T\d{4}(\.\d{3})?$", str(m.get("id", ""))):
            raise RuleError("{}: invalid MITRE technique id {!r}".format(rid, m.get("id")))
        if not m.get("name") or not m.get("tactic"):
            raise RuleError("{}: MITRE mapping {} needs 'name' and 'tactic'".format(rid, m.get("id")))
    if not mitre:
        raise RuleError("{}: every rule needs at least one MITRE ATT&CK mapping".format(rid))
    return Rule(id=raw["id"], name=raw["name"], type=raw["type"], severity=raw["severity"],
                description=raw.get("description", ""), sources=list(sources), params=params,
                mitre=mitre, response=list(raw.get("response") or []), enabled=raw.get("enabled", True))


def load_rules(path: Path | str | None = None) -> List[Rule]:
    """Load, validate and return the rules (disabled rules are kept but flagged)."""
    path = Path(path) if path else DEFAULT_RULES_PATH
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleError("rule file not found: {}".format(path))
    except json.JSONDecodeError as exc:
        raise RuleError("rule file is not valid JSON ({}): {}".format(path, exc))
    raw_rules = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleError("rule file must contain a non-empty 'rules' list")
    rules, seen = [], set()
    for i, raw in enumerate(raw_rules, 1):
        rule = _validate(raw, i)
        if rule.id in seen:
            raise RuleError("duplicate rule id {}".format(rule.id))
        seen.add(rule.id)
        rules.append(rule)
    return rules
