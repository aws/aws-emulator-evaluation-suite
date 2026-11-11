"""op-contract-describe-traffic-mirror-filter-rules."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-traffic-mirror-filter-rules"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorFilterRules: a rule created via CreateTrafficMirrorFilterRule
    round-trips exactly (success contract); an unrecognized filter name is the distinct
    error boundary."""
    ec2 = ctx.client("ec2")
    filter_id = ec2.create_traffic_mirror_filter(
        Description=ctx.unique_name("sim2real-behav-tmf-"),
        TagSpecifications=_tag_spec("traffic-mirror-filter"),
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="0.0.0.0/0",
        SourceCidrBlock="0.0.0.0/0",
        TagSpecifications=_tag_spec("traffic-mirror-filter-rule"),
    )["TrafficMirrorFilterRule"]
    rule_id = rule["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(
        lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_id)
    )

    resp = ec2.describe_traffic_mirror_filter_rules(TrafficMirrorFilterRuleIds=[rule_id])
    rules = resp["TrafficMirrorFilterRules"]
    assert len(rules) == 1, f"expected exactly 1 rule for {rule_id!r}, got {len(rules)}"
    assert rules[0]["RuleNumber"] == 1, f"expected RuleNumber 1, got {rules[0]['RuleNumber']!r}"
    assert rules[0]["RuleAction"] == "accept", (
        f"expected RuleAction 'accept', got {rules[0]['RuleAction']!r}"
    )
    assert rules[0]["TrafficDirection"] == "ingress", (
        f"expected TrafficDirection 'ingress', got {rules[0]['TrafficDirection']!r}"
    )

    # Positive control: a *recognized* filter name on the same rule, on the same wiring as
    # the negative below, so "rejects an unrecognized name" cannot be "rejects Filters at all".
    resp_ok = ec2.describe_traffic_mirror_filter_rules(
        Filters=[{"Name": "traffic-mirror-filter-rule-id", "Values": [rule_id]}]
    )
    rules_ok = resp_ok["TrafficMirrorFilterRules"]
    assert len(rules_ok) == 1 and rules_ok[0]["TrafficMirrorFilterRuleId"] == rule_id, (
        f"expected the recognized filter to match {rule_id!r}, got {rules_ok!r}"
    )

    # Error boundary: unrecognized filter name.
    code, code_message = _error_code(
        lambda: ec2.describe_traffic_mirror_filter_rules(
            Filters=[{"Name": "not-a-real-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_code_message = "The filter 'not-a-real-filter' is invalid"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _tag_spec(resource_type):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "1"}]}]


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
