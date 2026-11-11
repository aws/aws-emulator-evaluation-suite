"""op-contract-deleteAutoScalingGroup."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteAutoScalingGroup"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup without ForceDelete is rejected with ResourceInUse while the group
    has an InService instance and the group survives; ForceDelete=True removes it, and a mutation
    against the deleted name is rejected."""
    asg = ctx.client("autoscaling")
    group_name, _instance_id = _create_asg_with_instance(ctx, desired=1)

    # --- error boundary: non-empty group, no ForceDelete ---
    code, message = _error(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=group_name))
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code}"
    expected_message = (
        "You cannot delete an AutoScalingGroup while there are instances or pending Spot "
        "instance request(s) still in the group."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_there = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ]
    assert len(still_there) == 1, "group must not have been deleted by the rejected call"

    # --- positive control: ForceDelete=True succeeds and the group goes away ---
    asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)

    def _probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ]

    gone = _poll_until(_probe, lambda groups: groups == [], timeout_s=300.0, interval_s=10.0)
    assert gone == []

    # --- dead id: a mutation against the now-deleted group must also be rejected ---
    update_code, message = _error(
        lambda: asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MaxSize=5)
    )
    assert update_code == "ValidationError", (
        f"expected ValidationError updating a deleted group, got {update_code}"
    )
    expected_message = "AutoScalingGroup name not found - null"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]

    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in shared network")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg_with_instance(ctx, desired=1, min_size=0, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckType="EC2",
        HealthCheckGracePeriod=30,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_delete_group)

    def _probe():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ]
        return groups[0]["Instances"] if groups else []

    instances = _poll_until(
        _probe,
        lambda insts: len([i for i in insts if i["LifecycleState"] == "InService"]) >= desired,
        timeout_s=420.0,
        interval_s=10.0,
    )
    in_service = [i for i in instances if i["LifecycleState"] == "InService"]
    return group_name, (in_service[0]["InstanceId"] if in_service else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
