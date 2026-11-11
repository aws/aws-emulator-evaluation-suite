"""put-insight-rule-enable-disable-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-insight-rule-enable-disable-lifecycle"
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
    """PutInsightRule creates an ENABLED rule; DisableInsightRules/EnableInsightRules toggle its state."""
    cw = ctx.client("cloudwatch")
    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))
    log_group = ctx.unique_name("sim2real-behav-/cwprobe/loggroup-")

    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=_insight_rule_definition(log_group))

    def probe():
        return cw.describe_insight_rules()

    def find_rule(resp):
        return next((r for r in resp.get("InsightRules", []) if r["Name"] == rule_name), None)

    resp = _poll_until(probe, lambda r: find_rule(r) is not None, timeout_s=20, interval_s=2)
    rule = find_rule(resp)
    assert rule["State"] == "ENABLED", f"expected newly created rule to be ENABLED, got {rule['State']}"

    disable_resp = cw.disable_insight_rules(RuleNames=[rule_name])
    assert disable_resp.get("Failures", []) == [], f"unexpected DisableInsightRules failures: {disable_resp.get('Failures')}"
    resp = _poll_until(probe, lambda r: find_rule(r) and find_rule(r)["State"] == "DISABLED", timeout_s=20, interval_s=2)
    disabled_state = find_rule(resp)["State"]
    assert disabled_state == "DISABLED", f"expected DISABLED after DisableInsightRules, got {disabled_state}"

    enable_resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert enable_resp.get("Failures", []) == [], f"unexpected EnableInsightRules failures: {enable_resp.get('Failures')}"
    resp = _poll_until(probe, lambda r: find_rule(r) and find_rule(r)["State"] == "ENABLED", timeout_s=20, interval_s=2)
    enabled_state = find_rule(resp)["State"]
    assert enabled_state == "ENABLED", f"expected ENABLED after EnableInsightRules, got {enabled_state}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
