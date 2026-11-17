"""traffic-mirror-filter-rule-order-and-remove-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "traffic-mirror-filter-rule-order-and-remove-fields"
GROUP = "vpc-networking"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorFilters lists each direction's rules ascending by RuleNumber
    regardless of creation order, RuleNumber is scoped per direction, and
    ModifyTrafficMirrorFilterRule's RemoveFields resets the optional members it names."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmf-")
    filter_id = ec2.create_traffic_mirror_filter(
        Description=name, TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    # Three ingress rules, created out of numeric order.
    rule_ids = {}
    for number in (300, 50, 150):
        rid = ec2.create_traffic_mirror_filter_rule(
            TrafficMirrorFilterId=filter_id,
            TrafficDirection="ingress",
            RuleNumber=number,
            RuleAction="accept",
            DestinationCidrBlock="10.0.0.0/24",
            SourceCidrBlock="10.0.1.0/24",
        )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
        rule_ids[number] = rid
        ctx.on_cleanup(lambda rid=rid: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rid))

    # An egress rule reusing RuleNumber 50: direction scopes RuleNumber independently of ingress.
    egress_rule_id = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="egress",
        RuleNumber=50,
        RuleAction="reject",
        DestinationCidrBlock="10.0.2.0/24",
        SourceCidrBlock="10.0.3.0/24",
    )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=egress_rule_id))

    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])["TrafficMirrorFilters"][0]
    ingress_numbers = [r["RuleNumber"] for r in described["IngressFilterRules"]]
    assert ingress_numbers == [50, 150, 300], (
        f"expected ingress rules ordered ascending by RuleNumber [50, 150, 300], got {ingress_numbers!r}"
    )
    egress_numbers = [r["RuleNumber"] for r in described["EgressFilterRules"]]
    assert egress_numbers == [50], f"expected egress rules [50], got {egress_numbers!r}"

    # Give the RuleNumber-150 rule every optional member RemoveFields can clear.
    mid_rule_id = rule_ids[150]
    ec2.modify_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=mid_rule_id,
        Description="to be cleared",
        Protocol=6,
        SourcePortRange={"FromPort": 1024, "ToPort": 2048},
        DestinationPortRange={"FromPort": 80, "ToPort": 443},
    )
    populated = _find_rule(ec2, filter_id, mid_rule_id)
    assert populated["Description"] == "to be cleared", f"setup did not stick: {populated!r}"
    assert populated["Protocol"] == 6, f"setup did not stick: {populated!r}"
    assert populated["SourcePortRange"] == {"FromPort": 1024, "ToPort": 2048}, f"setup did not stick: {populated!r}"
    assert populated["DestinationPortRange"] == {"FromPort": 80, "ToPort": 443}, f"setup did not stick: {populated!r}"

    cleared = ec2.modify_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=mid_rule_id,
        RemoveFields=["description", "protocol", "source-port-range", "destination-port-range"],
    )["TrafficMirrorFilterRule"]
    for field in ("Description", "Protocol", "SourcePortRange", "DestinationPortRange"):
        assert field not in cleared, f"expected {field} absent from the modify response, got {cleared!r}"

    # Independent read, not just the mutating call's own echoed response.
    reread = _find_rule(ec2, filter_id, mid_rule_id)
    for field in ("Description", "Protocol", "SourcePortRange", "DestinationPortRange"):
        assert field not in reread, f"expected {field} absent on independent read, got {reread!r}"
    assert reread["RuleAction"] == "accept", f"RemoveFields must not touch other members, got {reread!r}"
    assert reread["DestinationCidrBlock"] == "10.0.0.0/24", f"RemoveFields must not touch other members, got {reread!r}"


def _find_rule(ec2, filter_id, rule_id):
    described = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])["TrafficMirrorFilters"][0]
    for r in described["IngressFilterRules"] + described["EgressFilterRules"]:
        if r["TrafficMirrorFilterRuleId"] == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found on filter {filter_id}")


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
