"""instance-refresh-checkpoint-delay."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "instance-refresh-checkpoint-delay"
GROUP = "visibility-timeout-ttl"
SERVICES = ["autoscaling"]

CHECKPOINT_DELAY_S = 20


# timing:real-time — cooldown: 20 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-adding-checkpoints-instance-refresh.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """StartInstanceRefresh with a checkpoint delay holds progression at the checkpoint for
    the configured wait time before advancing, visible via DescribeInstanceRefreshes."""
    asg = ctx.client("autoscaling")

    subnet_id = _get_default_subnet(ctx)
    lt_name = _create_launch_template(ctx)
    group_name = _create_asg_with_template(
        ctx, lt_name, subnet_id, min_size=2, max_size=2, desired=2, DefaultInstanceWarmup=0
    )

    # EC2 launch plus health checks can take well over two minutes, so allow 180 s.
    _wait_for_in_service_count(ctx, group_name, 2, timeout_s=180.0)

    # MinHealthyPercentage=0 lets both instances be replaced in a single batch; the low
    # (but non-terminal) checkpoint still exercises the hold-before-advancing behavior.
    refresh_id = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Preferences={
            "MinHealthyPercentage": 0,
            "InstanceWarmup": 0,
            "CheckpointPercentages": [1],
            "CheckpointDelay": CHECKPOINT_DELAY_S,
        },
    )["InstanceRefreshId"]
    ctx.on_cleanup(lambda: _best_effort_cancel_refresh(ctx, group_name))

    t_checkpoint = None
    t_done = None
    final_status = None
    # A single batch still involves real EC2 instance termination + launch + health checks on
    # top of the CheckpointDelay hold; on real AWS this routinely takes well over 3 minutes
    # end-to-end, so use a generous bound to avoid a false "never reached terminal state" failure.
    deadline = time.monotonic() + 480.0
    while time.monotonic() < deadline:
        refresh = asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, InstanceRefreshIds=[refresh_id]
        )["InstanceRefreshes"][0]
        pct = refresh.get("PercentageComplete", 0)
        status = refresh["Status"]
        if t_checkpoint is None and pct >= 1:
            t_checkpoint = time.monotonic()
        if status in ("Successful", "Failed", "Cancelled"):
            t_done = time.monotonic()
            final_status = status
            break
        time.sleep(5)

    assert final_status is not None, "instance refresh never reached a terminal state in time"
    assert final_status == "Successful", f"instance refresh ended with status={final_status!r}"
    assert t_checkpoint is not None, "instance refresh never reported reaching the checkpoint"

    held_seconds = t_done - t_checkpoint
    assert held_seconds >= CHECKPOINT_DELAY_S * 0.75, (
        f"checkpoint delay was not honored: only held at/past the checkpoint for "
        f"{held_seconds:.1f}s (expected close to the configured {CHECKPOINT_DELAY_S}s CheckpointDelay)"
    )


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:

    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError("no shared network VPC subnet available in this account/region")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_asg_with_template(
    ctx, lt_name: str, subnet_id: str, min_size: int, max_size: int, desired: int, **extra: Any
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asg-")
    params = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    params.update(extra)
    asg.create_auto_scaling_group(**params)
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))
    return name


def _wait_for_in_service_count(ctx, group_name: str, count: int, timeout_s: float, interval_s: float = 5.0) -> None:
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
        instances = groups[0]["Instances"] if groups else []
        in_service = [i for i in instances if i["LifecycleState"] == "InService"]
        if len(in_service) >= count:
            return
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {count} InService instance(s)")


def _best_effort_cancel_refresh(ctx, group_name: str) -> None:
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    try:
        asg.cancel_instance_refresh(AutoScalingGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ActiveInstanceRefreshNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
