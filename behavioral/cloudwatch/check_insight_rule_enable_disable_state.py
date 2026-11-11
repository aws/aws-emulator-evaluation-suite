"""insight-rule-enable-disable-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "insight-rule-enable-disable-state"
GROUP = "state"
SERVICES = ["cloudwatch"]

_RULE_DEFINITION = {
    "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
    "AggregateOn": "Count",
    "Contribution": {
        "Keys": ["$.client_ip"],
        "Filters": [],
    },
    "LogFormat": "JSON",
    "LogGroupNames": ["sim2real-behavioral-nonexistent-log-group"],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DisableInsightRules / EnableInsightRules move a Contributor Insights rule
    between ENABLED and DISABLED, observable via DescribeInsightRules."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-rule-")

    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=json.dumps(_RULE_DEFINITION),
        RuleState="ENABLED",
    )
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[rule_name]))

    def _rule_state() -> str:
        resp = cw.describe_insight_rules()
        for rule in resp["InsightRules"]:
            if rule["Name"] == rule_name:
                return rule["State"]
        raise AssertionError("rule disappeared from DescribeInsightRules")

    state = _poll_until(_rule_state, lambda s: s == "ENABLED", timeout_s=20, interval_s=2)
    assert state == "ENABLED", f"expected newly created rule ENABLED, saw {state}"

    resp = cw.disable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"unexpected disable failures: {resp.get('Failures')}"
    got = _poll_until(_rule_state, lambda s: s == "DISABLED", timeout_s=20, interval_s=2)
    assert got == "DISABLED", f"rule state did not become DISABLED, saw {got}"

    resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"unexpected enable failures: {resp.get('Failures')}"
    got = _poll_until(_rule_state, lambda s: s == "ENABLED", timeout_s=20, interval_s=2)
    assert got == "ENABLED", f"rule state did not become ENABLED again, saw {got}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

