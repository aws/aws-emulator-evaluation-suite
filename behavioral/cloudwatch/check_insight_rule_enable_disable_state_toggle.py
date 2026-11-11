"""insight-rule-enable-disable-state-toggle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "insight-rule-enable-disable-state-toggle"
GROUP = "state"
SERVICES = ["cloudwatch"]

_RULE_DEFINITION = {
    "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
    "AggregateOn": "Count",
    "Contribution": {"Filters": [], "Keys": ["$.ip"]},
    "LogFormat": "JSON",
    "LogGroupNames": ["sim2real-behavioral-nonexistent-log-group"],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """A newly created Contributor Insights rule starts ENABLED, and
    DisableInsightRules/EnableInsightRules toggle its State as seen via
    DescribeInsightRules."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-insight-")

    cw.put_insight_rule(
        RuleName=name,
        RuleDefinition=json.dumps(_RULE_DEFINITION),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[name]))

    _poll_until_state(ctx, name, "ENABLED", reason="a newly created rule to start ENABLED")

    disable_failures = cw.disable_insight_rules(RuleNames=[name]).get("Failures", [])
    assert disable_failures == [], f"expected no per-rule failures from DisableInsightRules, got {disable_failures}"
    _poll_until_state(ctx, name, "DISABLED", reason="the rule to become DISABLED after DisableInsightRules")

    enable_failures = cw.enable_insight_rules(RuleNames=[name]).get("Failures", [])
    assert enable_failures == [], f"expected no per-rule failures from EnableInsightRules, got {enable_failures}"
    _poll_until_state(ctx, name, "ENABLED", reason="the rule to become ENABLED again after EnableInsightRules")


def _rule_state(ctx, rule_name: str) -> str:
    cw = ctx.client("cloudwatch")
    rules = cw.describe_insight_rules(MaxResults=100)["InsightRules"]
    for rule in rules:
        if rule["Name"] == rule_name:
            return rule["State"]
    raise AssertionError(f"rule {rule_name!r} not found in DescribeInsightRules")


def _poll_until_state(
    ctx, rule_name: str, expected: str, *, reason: str, timeout_s: float = 20.0, interval_s: float = 2.0
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        last = _rule_state(ctx, rule_name)
        if last == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected {reason}, but DescribeInsightRules still reported {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
