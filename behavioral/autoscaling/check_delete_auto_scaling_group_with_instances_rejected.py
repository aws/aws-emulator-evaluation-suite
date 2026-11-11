"""delete-auto-scaling-group-with-instances-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-auto-scaling-group-with-instances-rejected"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup without ForceDelete is rejected with ResourceInUse while the
    group still has a running instance, and the group is NOT deleted; the same call with
    ForceDelete=True succeeds (positive control) and the group disappears."""
    autoscaling = ctx.client("autoscaling")
    asg_name = ctx.unique_name("sim2real-asg-")
    lt_name = ctx.unique_name("sim2real-lt-")

    ami_id = _latest_al2023_ami(ctx)
    subnet_ids, _vpc_id = _default_subnets(ctx)
    _create_launch_template(ctx, lt_name, ami_id)

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=",".join(subnet_ids),
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    cleanup_registered = {"done": False}

    def _cleanup():
        if not cleanup_registered["done"]:
            autoscaling.delete_auto_scaling_group(
                AutoScalingGroupName=asg_name, ForceDelete=True
            )

    ctx.on_cleanup(_cleanup)

    def _group_exists() -> bool:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        return len(groups) == 1

    def _has_inservice_instance() -> bool:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        return len(groups) == 1 and any(
            i["LifecycleState"] == "InService" for i in groups[0]["Instances"]
        )

    # Real AWS answers a delete attempted while the launch is still in flight with
    # ScalingActivityInProgress, not ResourceInUse — waiting for InService isolates the
    # "group not empty" rejection this check exists to assert.
    assert _poll_until(_has_inservice_instance, timeout_s=300, interval_s=10), (
        "no instance ever reached InService in the group within 300s"
    )

    code, message = _error_code(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name)
    )
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code!r}"
    assert message == (
        "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance "
        "request(s) still in the group."
    ), f"expected the exact non-empty-group refusal message, got {message!r}"

    # The forbidden effect did not happen: the group still exists.
    assert _group_exists(), "group disappeared despite the non-forced delete being rejected"

    # Positive control: the identical delete succeeds with ForceDelete=True.
    autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    cleanup_registered["done"] = True

    def _group_gone() -> bool:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        return len(groups) == 0

    assert _poll_until(_group_gone, timeout_s=180, interval_s=5), (
        "group still present after ForceDelete=True"
    )


def _poll_until(probe, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _default_subnets(ctx, count: int = 2):

    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available in this account/region")
    return [s["SubnetId"] for s in subnets[:count]], subnets[0]["VpcId"]


def _create_launch_template(ctx, lt_name: str, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    return lt_name


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
