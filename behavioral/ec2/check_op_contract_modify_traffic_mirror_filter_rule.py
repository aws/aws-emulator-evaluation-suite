"""op-contract-modify-traffic-mirror-filter-rule."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-traffic-mirror-filter-rule"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTrafficMirrorFilterRule: flipping RuleAction is observable on the filter's
    rule list, and mixing an IPv4 destination with an IPv6 source (they must be the same
    IP family) is rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmr-")
    filt = ec2.create_traffic_mirror_filter(
        Description="behavioral test filter", TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]
    filter_id = filt["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="10.0.0.0/24",
        SourceCidrBlock="10.0.1.0/24",
        Protocol=6,
    )["TrafficMirrorFilterRule"]
    rule_id = rule["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_id))
    assert rule["RuleAction"] == "accept", rule

    # success path
    modified = ec2.modify_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=rule_id, RuleAction="reject", Description="now-rejecting"
    )["TrafficMirrorFilterRule"]
    assert modified["RuleAction"] == "reject", modified
    assert modified["Description"] == "now-rejecting", modified

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    ingress_rules = described["IngressFilterRules"]
    persisted = next(r for r in ingress_rules if r["TrafficMirrorFilterRuleId"] == rule_id)
    assert persisted["RuleAction"] == "reject", persisted

    # error boundary: source and destination CIDR must be in the same IP family
    err, err_msg = _client_error(
        lambda: ec2.modify_traffic_mirror_filter_rule(
            TrafficMirrorFilterRuleId=rule_id, DestinationCidrBlock="2001:db8::/32"
        )
    )
    assert err == "InvalidParameterValue", f"expected InvalidParameterValue, got {err!r}"
    assert err_msg == "SourceCidrBlock and DestinationCidrBlock must both be IPv4 or both be IPv6 CIDR blocks", err_msg

    # effect-absent: the rejected IPv4/IPv6 mismatch must not have touched the persisted rule
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])[
        "TrafficMirrorFilters"
    ][0]
    unchanged = next(
        r for r in described["IngressFilterRules"] if r["TrafficMirrorFilterRuleId"] == rule_id
    )
    assert unchanged["DestinationCidrBlock"] == "10.0.0.0/24", (
        f"a rejected DestinationCidrBlock update must not persist, got {unchanged!r}"
    )


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
