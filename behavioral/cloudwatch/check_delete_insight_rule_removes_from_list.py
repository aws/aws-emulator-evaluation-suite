"""delete-insight-rule-removes-from-list."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-insight-rule-removes-from-list"
GROUP = 'insight-rules'
SERVICES = ['cloudwatch']

def _insight_rule_definition(log_group: str) -> str:
    # Real CloudWatch rejects a Contribution block without an explicit Filters
    # key: "INVALID_RULE_BODY: MissingKey encountered at Filters in the RuleBody".
    return json.dumps(
        {
            "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
            "LogGroupNames": [log_group],
            "LogFormat": "JSON",
            "Contribution": {"Keys": ["$.clientIp"], "Filters": []},
            "AggregateOn": "Count",
        }
    )

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """DeleteInsightRules reports no failure and removes the rule from DescribeInsightRules, and a
    later EnableInsightRules naming it reports it as its only Failures[] entry."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    log_group = ctx.unique_name("sim2real-behav-/cwprobe/loggroup-")
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))

    cw.put_insight_rule(
        RuleName=rule_name,
        RuleDefinition=_insight_rule_definition(log_group),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def probe():
        return cw.describe_insight_rules()

    def contains_rule(resp):
        return any(r["Name"] == rule_name for r in resp.get("InsightRules", []))

    _poll_until(probe, contains_rule, timeout_s=20, interval_s=2)

    resp = cw.delete_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"unexpected failures deleting insight rule: {resp.get('Failures')}"

    resp2 = _poll_until(probe, lambda r: not contains_rule(r), timeout_s=20, interval_s=2)
    assert not contains_rule(resp2), "deleted insight rule still present in DescribeInsightRules"

    # The rule is gone, not merely unlisted: a mutation naming it must also fail.
    # EnableInsightRules looks up by name and reports a nonexistent name as a
    # per-item Failures[] entry rather than raising.
    enable_resp = cw.enable_insight_rules(RuleNames=[rule_name])
    enable_failures = {f["FailureResource"] for f in enable_resp.get("Failures", [])}
    assert enable_failures == {rule_name}, (
        f"expected EnableInsightRules on the deleted rule to report it as the sole "
        f"failure, got {enable_resp.get('Failures')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
