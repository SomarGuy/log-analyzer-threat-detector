"""Compare engine output with the injected-attack ground truth of the synthetic dataset.

This answers a narrow, honest question: *does every rule fire on the attack it was written for, and
does the benign background noise stay quiet?* It says nothing about real-world detection accuracy
because the attacks and the rules were written by the same person.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def _matches(alert: Dict[str, Any], exp: Dict[str, str]) -> bool:
    if alert["rule_id"] != exp["rule"]:
        return False
    if "ip" in exp and exp["ip"] not in alert["source_ips"]:
        return False
    if "host" in exp and exp["host"] not in alert["hosts"]:
        return False
    if "user" in exp:
        d = alert.get("details", {})
        users = set(alert["users"]) | {d.get("new_account"), d.get("user")} | set(d.get("accounts_logged_in", []))
        if exp["user"] not in users:
            return False
    return True


def evaluate(report: Dict[str, Any], truth_path: str | Path) -> Dict[str, Any]:
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    alerts = report["alerts"]
    used = set()
    scenarios: List[Dict[str, Any]] = []
    expected_total = detected_total = 0
    for sc in truth["scenarios"]:
        results = []
        for exp in sc["expect"]:
            hits = [a for a in alerts if _matches(a, exp)]
            used.update(a["id"] for a in hits)
            results.append({**exp, "detected": bool(hits), "alert_ids": [a["id"] for a in hits]})
        expected_total += len(results)
        detected_total += sum(1 for r in results if r["detected"])
        scenarios.append({"scenario": sc["scenario"], "description": sc["description"], "results": results,
                          "fully_detected": all(r["detected"] for r in results)})
    unexpected = [a for a in alerts if a["id"] not in used]
    return {
        "scenarios_total": len(scenarios),
        "scenarios_fully_detected": sum(1 for s in scenarios if s["fully_detected"]),
        "expected_alerts": expected_total, "expected_alerts_detected": detected_total,
        "unexpected_alerts": [{"id": a["id"], "rule_id": a["rule_id"], "title": a["title"], "source_ips": a["source_ips"]} for a in unexpected],
        "scenarios": scenarios,
    }


def format_evaluation(ev: Dict[str, Any]) -> str:
    lines = ["Evaluation against injected ground truth (synthetic data only)",
             "  scenarios fully detected : {}/{}".format(ev["scenarios_fully_detected"], ev["scenarios_total"]),
             "  expected alerts detected : {}/{}".format(ev["expected_alerts_detected"], ev["expected_alerts"]),
             "  unexpected alerts        : {}".format(len(ev["unexpected_alerts"]))]
    for sc in ev["scenarios"]:
        lines.append("  [{}] {}".format("PASS" if sc["fully_detected"] else "MISS", sc["scenario"]))
        for r in sc["results"]:
            if not r["detected"]:
                lines.append("        missing {}".format({k: v for k, v in r.items() if k in ("rule", "ip", "host", "user")}))
    for a in ev["unexpected_alerts"]:
        lines.append("  unexpected: {} {} {} {}".format(a["id"], a["rule_id"], a["title"], ",".join(a["source_ips"])))
    return "\n".join(lines)
