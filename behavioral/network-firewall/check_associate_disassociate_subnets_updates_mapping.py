"""associate-disassociate-subnets-updates-mapping."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-disassociate-subnets-updates-mapping"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSubnets and DisassociateSubnets actually mutate Firewall.SubnetMappings:
    adding a second-AZ subnet grows the mapping to two entries and removing it again (while
    a first subnet remains) shrinks it back to one, with a fresh UpdateToken each time."""
    fw = _create_basic_firewall(ctx)
    nfw = fw["nfw"]
    ec2 = fw["ec2"]

    az2 = next(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"] if z["ZoneName"] != fw["az"]
    )
    subnet2_id = ec2.create_subnet(
        VpcId=fw["vpc_id"], CidrBlock="10.88.2.0/24", AvailabilityZone=az2,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": fw["name"] + "-subnet2"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet2_id)))

    token_before = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])["UpdateToken"]
    assoc = nfw.associate_subnets(
        FirewallArn=fw["firewall_arn"], UpdateToken=token_before, SubnetMappings=[{"SubnetId": subnet2_id}],
    )
    assoc_ids = {m["SubnetId"] for m in assoc["SubnetMappings"]}
    expected_assoc_ids = {fw["subnet_id"], subnet2_id}
    assert assoc_ids == expected_assoc_ids, (
        f"AssociateSubnets response mapping: expected {expected_assoc_ids}, got {assoc_ids}"
    )
    assert assoc["UpdateToken"] != token_before, (
        f"AssociateSubnets UpdateToken did not change: still {token_before!r}"
    )

    disassoc = nfw.disassociate_subnets(
        FirewallArn=fw["firewall_arn"], UpdateToken=assoc["UpdateToken"], SubnetIds=[subnet2_id],
    )
    disassoc_ids = {m["SubnetId"] for m in disassoc["SubnetMappings"]}
    expected_disassoc_ids = {fw["subnet_id"]}
    assert disassoc_ids == expected_disassoc_ids, (
        f"DisassociateSubnets response mapping: expected {expected_disassoc_ids}, got {disassoc_ids}"
    )
    assert disassoc["UpdateToken"] != assoc["UpdateToken"], (
        f"DisassociateSubnets UpdateToken did not change: still {assoc['UpdateToken']!r}"
    )

    final = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
    final_ids = {m["SubnetId"] for m in final["Firewall"]["SubnetMappings"]}
    assert final_ids == expected_disassoc_ids, (
        f"independent DescribeFirewall read after disassociate: expected {expected_disassoc_ids}, got {final_ids}"
    )


def _retry_dependency(fn, timeout_s=180, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_basic_firewall(ctx, *, delete_protection=False, subnet_change_protection=False,
                            firewall_policy_change_protection=False, stateful_rule_group_arn=None):
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    name = ctx.unique_name("sim2real-nfw-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.88.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name + "-subnet"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    policy_doc = {
        "StatelessDefaultActions": ["aws:forward_to_sfe"],
        "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
    }
    if stateful_rule_group_arn:
        policy_doc["StatefulRuleGroupReferences"] = [{"ResourceArn": stateful_rule_group_arn}]
    policy_name = ctx.unique_name("sim2real-nfw-policy-")
    policy_resp = nfw.create_firewall_policy(FirewallPolicyName=policy_name, FirewallPolicy=policy_doc)
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn))

    fw_resp = nfw.create_firewall(
        FirewallName=name,
        FirewallPolicyArn=policy_arn,
        VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": subnet_id}],
        DeleteProtection=delete_protection,
        SubnetChangeProtection=subnet_change_protection,
        FirewallPolicyChangeProtection=firewall_policy_change_protection,
    )
    firewall_arn = fw_resp["Firewall"]["FirewallArn"]
    update_token = nfw.describe_firewall(FirewallArn=firewall_arn)["UpdateToken"]

    def _del_firewall():
        try:
            nfw.update_firewall_delete_protection(FirewallArn=firewall_arn, DeleteProtection=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            nfw.delete_firewall(FirewallArn=firewall_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        for _ in range(90):
            try:
                nfw.describe_firewall(FirewallArn=firewall_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            time.sleep(5)

    ctx.on_cleanup(_del_firewall)

    return {
        "nfw": nfw, "ec2": ec2, "name": name, "vpc_id": vpc_id, "subnet_id": subnet_id, "az": az,
        "policy_name": policy_name, "policy_arn": policy_arn, "firewall_arn": firewall_arn,
        "update_token": update_token,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
