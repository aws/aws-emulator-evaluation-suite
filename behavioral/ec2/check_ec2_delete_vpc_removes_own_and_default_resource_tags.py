"""ec2-delete-vpc-removes-own-and-default-resource-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ec2-delete-vpc-removes-own-and-default-resource-tags"
GROUP = "vpc-tag-cleanup"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteVpc, DescribeTags answers nothing for the VPC, its default security group, main
    route table and default network ACL, while the default group's rule keeps its tag (DescribeTags
    still answers for a security-group-rule id after its group is gone).
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.232.0.0/16")["Vpc"]["VpcId"]
    deleted = {"value": False}
    ctx.on_cleanup(lambda: None if deleted["value"] else ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]

    group_id = next(
        g["GroupId"] for g in ec2.describe_security_groups(Filters=vpc_filter)["SecurityGroups"] if g["GroupName"] == "default"
    )
    route_table_id = next(
        rt["RouteTableId"]
        for rt in ec2.describe_route_tables(Filters=vpc_filter)["RouteTables"]
        if any(a.get("Main") for a in rt["Associations"])
    )
    acl_id = next(a["NetworkAclId"] for a in ec2.describe_network_acls(Filters=vpc_filter)["NetworkAcls"] if a["IsDefault"])
    rule_id = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group_id]}])["SecurityGroupRules"][0][
        "SecurityGroupRuleId"
    ]

    owned_ids = [vpc_id, group_id, route_table_id, acl_id]
    all_ids = owned_ids + [rule_id]
    tag_value = ctx.unique_name("sim2real-behav-vpctag-")
    ec2.create_tags(Resources=all_ids, Tags=[{"Key": "Name", "Value": tag_value}])

    all_filter = [{"Name": "resource-id", "Values": all_ids}]
    before = ec2.describe_tags(Filters=all_filter)["Tags"]
    assert len(before) == len(all_ids), f"expected {len(all_ids)} tagged resources ({all_ids!r}), got {before!r}"

    ec2.delete_vpc(VpcId=vpc_id)
    deleted["value"] = True

    owned_filter = [{"Name": "resource-id", "Values": owned_ids}]
    after = ec2.describe_tags(Filters=owned_filter)["Tags"]
    assert after == [], f"expected every tag on the deleted VPC and its default resources to be gone, got {after!r}"

    rule_tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [rule_id]}])["Tags"]
    assert len(rule_tags) == 1 and rule_tags[0]["Value"] == tag_value, (
        f"expected the orphaned security-group-rule tag on {rule_id} to survive the VPC delete "
        f"(real-AWS behaviour), got {rule_tags!r}"
    )


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"VPC {vpc_id} never became available within {timeout_s}s (last {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
