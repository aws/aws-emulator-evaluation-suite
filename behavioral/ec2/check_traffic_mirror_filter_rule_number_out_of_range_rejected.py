"""traffic-mirror-filter-rule-number-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "traffic-mirror-filter-rule-number-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrafficMirrorFilterRule rejects a RuleNumber of 0 with the field's valid range, while
    the boundary value 1 is accepted and visible on the filter.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTrafficMirrorFilterRule.html
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmfr-")

    filt = ec2.create_traffic_mirror_filter(
        Description="sim2real behavioral filter",
        TagSpecifications=[_tag_spec("traffic-mirror-filter", name)],
    )["TrafficMirrorFilter"]
    filter_id = filt["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule_kwargs = dict(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleAction="accept",
        DestinationCidrBlock="10.0.0.0/24",
        SourceCidrBlock="10.0.1.0/24",
    )

    # error boundary: RuleNumber 0 is below the field's valid range of 1-32766.
    code, message = _error_code(
        lambda: ec2.create_traffic_mirror_filter_rule(RuleNumber=0, **rule_kwargs)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "RuleNumber is outside the allowed range of 1-32766", message

    # effect-absent: the refused create must not have added a rule to the filter.
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    assert described["IngressFilterRules"] == [], (
        f"a refused RuleNumber=0 create must leave the filter without rules, got "
        f"{described['IngressFilterRules']!r}"
    )

    # positive control: the boundary value 1 is the rule's legal neighbour and is accepted.
    rule = ec2.create_traffic_mirror_filter_rule(RuleNumber=1, **rule_kwargs)["TrafficMirrorFilterRule"]
    rule_id = rule["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_id))
    assert rule["RuleNumber"] == 1, f"expected RuleNumber 1 on create response, got {rule['RuleNumber']!r}"

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    numbers = [r["RuleNumber"] for r in described["IngressFilterRules"]]
    assert numbers == [1], f"expected exactly the rule numbered 1 on {filter_id}, got {numbers!r}"


def _error_code(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
