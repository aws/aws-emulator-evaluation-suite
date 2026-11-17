"""traffic-mirror-filter-rule-port-range-requires-tcp-udp-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "traffic-mirror-filter-rule-port-range-requires-tcp-udp-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrafficMirrorFilterRule rejects a DestinationPortRange with no Protocol set, while
    the same port range with Protocol=tcp (6) is accepted and visible on the filter.

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

    port_range = {"FromPort": 443, "ToPort": 443}
    rule_kwargs = dict(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="10.0.0.0/24",
        SourceCidrBlock="10.0.1.0/24",
        DestinationPortRange=port_range,
    )

    # error boundary: a destination port range with no Protocol set.
    code, message = _error_code(lambda: ec2.create_traffic_mirror_filter_rule(**rule_kwargs))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "DestinationPortRage is only supported for protocols TCP (6) and UDP (17)"
    ), message

    # effect-absent: the refused create must not have added a rule to the filter.
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    assert described["IngressFilterRules"] == [], (
        f"a refused port-range-without-protocol create must leave the filter without rules, "
        f"got {described['IngressFilterRules']!r}"
    )

    # positive control: the same rule, with Protocol=tcp (6), is accepted.
    rule = ec2.create_traffic_mirror_filter_rule(Protocol=6, **rule_kwargs)["TrafficMirrorFilterRule"]
    rule_id = rule["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_id))
    assert rule["Protocol"] == 6, f"expected Protocol 6 on create response, got {rule['Protocol']!r}"
    assert rule["DestinationPortRange"] == port_range, (
        f"expected DestinationPortRange {port_range!r} on create response, got "
        f"{rule['DestinationPortRange']!r}"
    )

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    persisted = next(
        r for r in described["IngressFilterRules"] if r["TrafficMirrorFilterRuleId"] == rule_id
    )
    assert persisted["DestinationPortRange"] == port_range, (
        f"expected the persisted rule to carry DestinationPortRange {port_range!r}, got "
        f"{persisted['DestinationPortRange']!r}"
    )


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
