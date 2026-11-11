"""associate-firewall-policy-updates-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-firewall-policy-updates-reference"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFirewallPolicy actually swaps which policy a firewall uses: DescribeFirewall
    reflects the new FirewallPolicyArn afterwards, and the firewall's original policy is no
    longer referenced by it (so it can be deleted once nothing else uses it)."""
    fw = _create_basic_firewall(ctx)
    nfw = fw["nfw"]

    policy_b_name = ctx.unique_name("sim2real-nfw-policy-b-")
    policy_b = nfw.create_firewall_policy(
        FirewallPolicyName=policy_b_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
        },
    )
    policy_b_arn = policy_b["FirewallPolicyResponse"]["FirewallPolicyArn"]
    policy_b_cleaned = {"done": False}

    def _cleanup_policy_b():
        if not policy_b_cleaned["done"]:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_b_arn)
            policy_b_cleaned["done"] = True

    ctx.on_cleanup(_cleanup_policy_b)

    before = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
    assert before["Firewall"]["FirewallPolicyArn"] == fw["policy_arn"], (
        f"expected firewall to start on {fw['policy_arn']}, got {before['Firewall']['FirewallPolicyArn']}"
    )
    token = before["UpdateToken"]

    nfw.associate_firewall_policy(
        FirewallArn=fw["firewall_arn"], UpdateToken=token, FirewallPolicyArn=policy_b_arn,
    )

    after = nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
    assert after["Firewall"]["FirewallPolicyArn"] == policy_b_arn, (
        f"expected AssociateFirewallPolicy to switch the reference to {policy_b_arn}, "
        f"got {after['Firewall']['FirewallPolicyArn']}"
    )

    # the original policy is no longer referenced by this firewall, so it can be deleted now.
    # The association swap propagates asynchronously, so poll for deletability.
    _delete_firewall_policy_when_free(nfw, fw["policy_arn"])
    fw["policy_state"]["deleted"] = True

    # tear down the firewall now (rather than relying on LIFO cleanup order) so that
    # policy_b -- which the firewall currently references -- becomes deletable next.
    try:
        nfw.update_firewall_delete_protection(FirewallArn=fw["firewall_arn"], DeleteProtection=False)
    except ClientError:
        pass
    nfw.delete_firewall(FirewallArn=fw["firewall_arn"])
    fw_deadline = time.monotonic() + 300
    while time.monotonic() < fw_deadline:
        try:
            nfw.describe_firewall(FirewallArn=fw["firewall_arn"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                break
            raise
        time.sleep(5)

    # policy_b was still referenced by the firewall until the delete above completed; that
    # dissociation also propagates asynchronously, so it needs the same bounded retry.
    _delete_firewall_policy_when_free(nfw, policy_b_arn)
    policy_b_cleaned["done"] = True


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


def _delete_firewall_policy_when_free(nfw, policy_arn, timeout_s=120, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidOperationException" and time.monotonic() < deadline:
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
    policy_state = {"deleted": False}

    def _del_policy():
        if not policy_state["deleted"]:
            try:
                nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_del_policy)

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
        "update_token": update_token, "policy_state": policy_state,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
