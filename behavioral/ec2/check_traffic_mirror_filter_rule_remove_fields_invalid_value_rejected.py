"""traffic-mirror-filter-rule-remove-fields-invalid-value-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "traffic-mirror-filter-rule-remove-fields-invalid-value-rejected"
GROUP = "vpc-networking"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyTrafficMirrorFilterRule rejects a RemoveFields entry that does not name one of
    the rule's removable properties, and a removable one still clears right after."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmfr-")
    filter_id = ec2.create_traffic_mirror_filter(
        Description=name, TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule_id = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="10.0.0.0/24",
        SourceCidrBlock="10.0.1.0/24",
        Description="original",
    )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_id))

    _NOT_A_REMOVABLE_FIELD = ("InvalidParameterValue", "No Field exists with name: rule-number")
    expect_error(
        lambda: ec2.modify_traffic_mirror_filter_rule(
            TrafficMirrorFilterRuleId=rule_id, RemoveFields=["rule-number"]
        ),
        *_NOT_A_REMOVABLE_FIELD,
    )

    # effect-absent: the rejected RemoveFields call must not have touched the rule.
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])["TrafficMirrorFilters"][0]
    unchanged = next(r for r in described["IngressFilterRules"] if r["TrafficMirrorFilterRuleId"] == rule_id)
    assert unchanged["Description"] == "original", f"a rejected RemoveFields must not mutate the rule: {unchanged!r}"
    assert unchanged["RuleNumber"] == 1, f"a rejected RemoveFields must not mutate the rule: {unchanged!r}"

    # Positive control, same rule, right after: a genuinely removable field still clears.
    cleared = ec2.modify_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=rule_id, RemoveFields=["description"]
    )["TrafficMirrorFilterRule"]
    assert "Description" not in cleared, f"expected Description cleared, got {cleared!r}"


def expect_error(fn, code, message):
    """Call fn(); assert its ClientError carries exactly (code, message). An unexpected
    success raises, so an emulator accepting input real AWS refuses cannot read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        actual_code, actual_message = err.get("Code"), err.get("Message")
        assert actual_code == code, f"expected code {code!r}, got {actual_code!r}"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected ({code!r}, {message!r}), but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
