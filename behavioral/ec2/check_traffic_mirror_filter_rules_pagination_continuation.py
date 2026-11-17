"""traffic-mirror-filter-rules-pagination-continuation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "traffic-mirror-filter-rules-pagination-continuation"
GROUP = "vpc-networking"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorFilterRules pages at its minimum MaxResults and a NextToken
    continuation returns exactly the remaining rules, with none dropped or duplicated."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmfr-page-")
    filter_id = ec2.create_traffic_mirror_filter(
        Description=name, TagSpecifications=[_tag_spec("traffic-mirror-filter", name)]
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    # One rule more than the minimum MaxResults (5), so a page boundary is forced.
    rule_ids = set()
    for number in range(1, 7):
        rid = ec2.create_traffic_mirror_filter_rule(
            TrafficMirrorFilterId=filter_id,
            TrafficDirection="ingress",
            RuleNumber=number,
            RuleAction="accept",
            DestinationCidrBlock="10.0.0.0/24",
            SourceCidrBlock="10.0.1.0/24",
        )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
        rule_ids.add(rid)
        ctx.on_cleanup(lambda rid=rid: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rid))

    # TrafficMirrorFilterId (not Filters, which is applied after the MaxResults slice and so
    # cannot be relied on to keep a page at full size in a shared account) scopes server-side.
    first_page = ec2.describe_traffic_mirror_filter_rules(TrafficMirrorFilterId=filter_id, MaxResults=5)
    first_ids = [r["TrafficMirrorFilterRuleId"] for r in first_page["TrafficMirrorFilterRules"]]
    assert len(first_ids) == 5, f"expected exactly 5 rules on the first page, got {len(first_ids)}"
    next_token = first_page.get("NextToken")
    assert next_token, "expected a NextToken when more rules remain"

    second_page = ec2.describe_traffic_mirror_filter_rules(
        TrafficMirrorFilterId=filter_id, MaxResults=5, NextToken=next_token
    )
    second_ids = [r["TrafficMirrorFilterRuleId"] for r in second_page["TrafficMirrorFilterRules"]]
    assert len(second_ids) == 1, f"expected exactly the 1 remaining rule on the second page, got {len(second_ids)}"
    assert not second_page.get("NextToken"), (
        f"expected no further NextToken once all 6 rules are returned, got {second_page.get('NextToken')!r}"
    )

    combined = set(first_ids) | set(second_ids)
    assert set(first_ids).isdisjoint(second_ids), f"page overlap: {set(first_ids) & set(second_ids)!r}"
    assert combined == rule_ids, (
        f"pagination lost or duplicated rules: expected {rule_ids!r}, got {combined!r}"
    )


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
