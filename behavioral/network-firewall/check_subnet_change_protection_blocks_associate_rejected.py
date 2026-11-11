"""subnet-change-protection-blocks-associate-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-change-protection-blocks-associate-rejected"
GROUP = "overly-permissive"
SERVICES = ["network-firewall"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSubnets on a firewall created with SubnetChangeProtection=True is rejected
    with InvalidOperationException, the subnet mapping is unchanged, and disabling the
    protection flag lets the same call succeed (positive control)."""
    fw = _create_basic_firewall(ctx, subnet_change_protection=True)
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

    before = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])["Firewall"]["SubnetMappings"]
    assert len(before) == 1

    code, message = _error(lambda: nfw.associate_subnets(
        FirewallArn=fw["firewall_arn"], SubnetMappings=[{"SubnetId": subnet2_id}],
    ))
    assert code == "InvalidOperationException", f"expected InvalidOperationException, got {code}"
    expected_message = "Cannot AssociateSubnets because SubnetChangeProtection is on"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: still just the original subnet mapping
    after_rejected = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])["Firewall"]["SubnetMappings"]
    assert {m["SubnetId"] for m in after_rejected} == {fw["subnet_id"]}

    # positive control: disabling protection lets the association go through
    nfw.update_subnet_change_protection(FirewallArn=fw["firewall_arn"], SubnetChangeProtection=False)
    nfw.associate_subnets(FirewallArn=fw["firewall_arn"], SubnetMappings=[{"SubnetId": subnet2_id}])
    after_allowed = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])["Firewall"]["SubnetMappings"]
    assert {m["SubnetId"] for m in after_allowed} == {fw["subnet_id"], subnet2_id}


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _delete_policy_when_free(nfw, policy_arn, timeout_s=300):
    """Teardown: DeleteFirewallPolicy, retrying while the deleted firewall's association drains."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidOperationException" or time.monotonic() > deadline:
                raise
            time.sleep(10)


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
    ctx.on_cleanup(lambda: _delete_policy_when_free(nfw, policy_arn))

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
