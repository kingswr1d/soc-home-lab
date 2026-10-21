#!/usr/bin/env python3
"""
Test the Sigma rules in detections/rules/ against JSON test logs.

For every rule file `detections/rules/<name>.yml` there is a test log
`detections/test_logs/<name>.json` (a list of events). The test passes when:

  1. the rule's top-level alert fires on its own test log, and
  2. NO rule fires on detections/test_logs/benign_controls.json.

Rules are parsed with pySigma (the library behind sigma-cli), so the test
runs the same detection logic that gets converted to Splunk / Elastic / KQL.
Correlation rules (event_count, temporal / temporal_ordered) are evaluated
too, using each event's Timestamp / EventTime field.

"Building block" rules (level: informational, or referenced by a
correlation) are not alerts on their own and are not required to fire.

Usage:
  python detections/tests/run_tests.py          # exit 0 = all pass
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression,
                              ConditionNOT, ConditionOR, ConditionValueExpression)
from sigma.correlations import SigmaCorrelationRule
from sigma.modifiers import SigmaContainsModifier, SigmaEndswithModifier, SigmaStartswithModifier
from sigma.rule import SigmaRule
from sigma.types import SigmaNull, SigmaNumber, SigmaRegularExpression, SigmaString

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
LOGS = ROOT / "test_logs"


# --------------------------------------------------------------------------
# single-event matching
# --------------------------------------------------------------------------
def value_matches(field_value, sigma_value) -> bool:
    if field_value is None:
        return isinstance(sigma_value, SigmaNull)
    if isinstance(sigma_value, SigmaNumber):
        try:
            return float(field_value) == float(sigma_value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(sigma_value, SigmaRegularExpression):
        flags = 0
        for f in sigma_value.flags:
            flags |= {"IGNORECASE": re.I, "MULTILINE": re.M, "DOTALL": re.S}[f.name]
        return re.search(sigma_value.regexp.to_plain(), str(field_value), flags) is not None
    if isinstance(sigma_value, SigmaString):
        # Sigma string matching is case-insensitive; wildcards become regex.
        pattern = sigma_value.to_regex().regexp.to_plain()
        return re.fullmatch(pattern, str(field_value), re.I | re.S) is not None
    return str(field_value).lower() == str(sigma_value).lower()


def eval_condition(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(eval_condition(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(eval_condition(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not eval_condition(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return value_matches(event.get(node.field), node.value)
    if isinstance(node, ConditionValueExpression):  # keyword search: any field
        return any(value_matches(v, node.value) for v in event.values())
    raise TypeError(f"unsupported condition node: {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    return any(eval_condition(cond.parsed, event) for cond in rule.detection.parsed_condition)


# --------------------------------------------------------------------------
# correlation rules
# --------------------------------------------------------------------------
def ts(event: dict) -> float:
    raw = event.get("Timestamp") or event.get("EventTime")
    if raw is None:
        raise ValueError(f"event has no Timestamp/EventTime: {event}")
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()


def hits(rule, events, by_name) -> list[tuple[float, tuple, dict]]:
    """Return (time, group_key, event) for every point where `rule` fires.

    For a plain rule that is every matching event. For a correlation rule it is
    the event that completes the correlation, keyed by the group-by fields."""
    if isinstance(rule, SigmaRule):
        return [(ts(e), (), e) for e in events if rule_matches(rule, e)]

    group_by = list(rule.group_by or [])
    window = rule.timespan.seconds

    def key(e):
        return tuple(e.get(f) for f in group_by)

    sub = [hits(by_name[ref.rule.name], events, by_name) for ref in rule.rules]
    out = []
    if rule.type.name.lower() == "event_count":
        op, need = rule.condition.op.name.lower(), rule.condition.count
        groups = defaultdict(list)
        for t, _, e in sub[0]:
            groups[key(e)].append((t, e))
        for k, items in groups.items():
            items.sort(key=lambda x: x[0])
            for i, (t, e) in enumerate(items):
                n = sum(1 for t2, _ in items[: i + 1] if t - t2 <= window)
                if {"gte": n >= need, "gt": n > need, "eq": n == need,
                    "lte": False, "lt": False}.get(op, False):
                    out.append((t, k, e))
                    break
        return out

    if rule.type.name.lower() in ("temporal", "temporal_ordered"):
        ordered = rule.type.name.lower() == "temporal_ordered"
        per_rule = []
        for s in sub:
            g = defaultdict(list)
            for t, _, e in s:
                g[key(e)].append((t, e))
            per_rule.append(g)
        for k in set.intersection(*(set(g) for g in per_rule)):
            first = per_rule[0][k]
            for t0, _ in first:
                last, ok = t0, True
                for g in per_rule[1:]:
                    cands = [(t, e) for t, e in g[k]
                             if (t >= last if ordered else True) and abs(t - t0) <= window]
                    if not cands:
                        ok = False
                        break
                    last = min(t for t, _ in cands)
                if ok:
                    out.append((last, k, g[k][0][1]))
                    break
        return out

    raise ValueError(f"unsupported correlation type: {rule.type}")


# --------------------------------------------------------------------------
def load(path: Path):
    col = SigmaCollection.load_ruleset([str(path)])
    col.resolve_rule_references()
    rules = list(col.rules)
    by_name = {r.name: r for r in rules if r.name}
    referenced = {ref.rule.name for r in rules if isinstance(r, SigmaCorrelationRule) for ref in r.rules}
    alerts = [r for r in rules
              if r.name not in referenced
              and not (r.level and r.level.name.lower() == "informational")]
    return rules, alerts, by_name


def main() -> int:
    benign = json.loads((LOGS / "benign_controls.json").read_text())
    failures = 0
    print(f"{'rule file':38s} {'alert':58s} {'attack log':12s} benign")
    print("-" * 120)
    for path in sorted(RULES.glob("*.yml")):
        _, alerts, by_name = load(path)
        log = LOGS / f"{path.stem}.json"
        events = json.loads(log.read_text()) if log.exists() else None
        for rule in alerts:
            if events is None:
                attack = "NO TEST LOG"
                failures += 1
            else:
                n = len(hits(rule, events, by_name))
                attack = f"fires ({n})" if n else "MISSED"
                failures += n == 0
            fp = len(hits(rule, benign, by_name))
            failures += fp > 0
            print(f"{path.name:38s} {rule.title[:58]:58s} {attack:12s} "
                  f"{'clean' if fp == 0 else f'FALSE POSITIVE ({fp})'}")
    print("-" * 120)
    print("PASS" if failures == 0 else f"FAIL: {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
