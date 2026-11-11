"""insight-rule-enable-disable-state-transition."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "insight-rule-enable-disable-state-transition"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """A Contributor Insights rule created via PutInsightRule starts ENABLED, transitions
    to DISABLED via DisableInsightRules, and back to ENABLED via EnableInsightRules —
    each reflected in DescribeInsightRules."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-rule-")
    rule_definition = {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "AggregateOn": "Count",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "LogFormat": "JSON",
        "LogGroupNames": [ctx.unique_name("sim2real-behav-loggroup-")],
    }

    cw.put_insight_rule(RuleName=name, RuleDefinition=json.dumps(rule_definition))
    ctx.on_cleanup(lambda: cw.delete_insight_rules(RuleNames=[name]))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rule_arn = f"arn:aws:cloudwatch:{ctx.region}:{account_id}:insight-rule/{name}"
    cw.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": "behavioral"}])

    def state_of(rule_name):
        rules = cw.describe_insight_rules()["InsightRules"]
        for r in rules:
            if r["Name"] == rule_name:
                return r["State"]
        return None

    state = _poll_until(lambda: state_of(name), lambda s: s == "ENABLED", timeout_s=30.0, interval_s=2.0)
    assert state == "ENABLED", f"expected new rule ENABLED, saw {state}"

    failures = cw.disable_insight_rules(RuleNames=[name]).get("Failures", [])
    assert failures == [], f"expected no disable failures, saw {failures}"
    state = _poll_until(lambda: state_of(name), lambda s: s == "DISABLED", timeout_s=30.0, interval_s=2.0)
    assert state == "DISABLED", f"expected DISABLED after disable, saw {state}"

    failures = cw.enable_insight_rules(RuleNames=[name]).get("Failures", [])
    assert failures == [], f"expected no enable failures, saw {failures}"
    state = _poll_until(lambda: state_of(name), lambda s: s == "ENABLED", timeout_s=30.0, interval_s=2.0)
    assert state == "ENABLED", f"expected ENABLED after re-enable, saw {state}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
