"""delete-auto-scaling-group-with-target-group-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-auto-scaling-group-with-target-group-attached-rejected"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup without ForceDelete is rejected with ResourceInUse while an attached
    instance remains (a target group is attached too) and leaves the group intact; once the
    instance is detached, the identical delete succeeds."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    autoscaling = ctx.client("autoscaling")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to create the test "
            "target group in; adapt to a non-shared network VPC to close this gap"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnet = _default_subnet(ctx, vpc_id)
    ami = _get_al2023_ami(ctx)
    lt_name = _create_dummy_launch_template(ctx, ami)

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        AvailabilityZones=[subnet["AvailabilityZone"]],
        VPCZoneIdentifier=subnet["SubnetId"],
        Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _safe_delete_group(autoscaling, asg_name))

    tg_name = ctx.unique_name("sim2real-tg-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    autoscaling.attach_load_balancer_target_groups(
        AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_arn]
    )

    run_resp = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    autoscaling.attach_instances(AutoScalingGroupName=asg_name, InstanceIds=[instance_id])
    _wait_for_membership(ctx, asg_name, {instance_id}, timeout_s=240.0)

    def _delete_attempt():
        return _error_code(
            lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name)
        )

    # DeleteAutoScalingGroup can transiently report ScalingActivityInProgress while the
    # attach's own scaling activity is still resolving even though the instance already
    # shows InService -- retry through that (and ResourceContention) and assert only on
    # the steady-state response. Note AWS's wire-level Error.Code drops the "Fault" suffix
    # the modeled shape carries (ResourceInUseFault -> ResourceInUse on the wire).
    code, message = _poll_until(
        _delete_attempt, lambda cm: cm[0] not in _TRANSIENT_CODES, timeout_s=120.0, interval_s=5.0
    )
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code!r}"
    assert message == (
        "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance "
        "request(s) still in the group."
    ), f"expected the exact non-empty-group refusal message, got {message!r}"

    # effect absent: the group must still exist
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ]
    assert len(groups) == 1, f"expected {asg_name} to still exist after the rejected delete, found {groups!r}"

    # positive control: once the instance is detached (and terminated), delete succeeds
    autoscaling.detach_instances(
        AutoScalingGroupName=asg_name,
        InstanceIds=[instance_id],
        ShouldDecrementDesiredCapacity=True,
    )
    ec2.terminate_instances(InstanceIds=[instance_id])
    _wait_for_membership(ctx, asg_name, set(), timeout_s=90.0)

    _retry_transient(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name),
        timeout_s=300.0,
        interval_s=5.0,
    )
    # DeleteAutoScalingGroup is itself asynchronous: the group lingers with
    # Status="Delete in progress" for a while after the call returns, so the
    # independent read must be polled, not asserted on the very next call.
    _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ],
        lambda gs: gs == [],
        timeout_s=180.0,
        interval_s=5.0,
    )


def _default_subnet(ctx, vpc_id: str) -> dict:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError(
            "no shared-network subnet available in the run's shared network to launch the test "
            "instance into; adapt to a non-shared-network subnet to close this gap"
        )
    return subnets[0]


def _get_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _create_dummy_launch_template(ctx, ami: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected success raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_group(autoscaling, name: str) -> None:
    """Teardown: force-delete the group; tolerate only its not-found, retry a transient refusal
    (an in-flight scaling activity, resource contention) for 60 s, and raise anything else."""
    deadline = time.monotonic() + 60
    while True:
        try:
            autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ValidationError" and "not found" in error.get("Message", ""):
                return
            if error.get("Code") not in _TRANSIENT_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


_TRANSIENT_CODES = {"ScalingActivityInProgress", "ResourceContention"}


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_transient(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    """Call fn(); retry through the transient ScalingActivityInProgress/ResourceContention
    codes AWS can return while an earlier scaling activity is still resolving. Any other
    ClientError -- a genuine failure -- is raised immediately, never retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _TRANSIENT_CODES and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_membership(
    ctx, asg_name: str, expected_ids: set[str], timeout_s: float = 60.0, interval_s: float = 3.0
) -> set[str]:
    autoscaling = ctx.client("autoscaling")
    current: set[str] = set()
    deadline = time.monotonic() + timeout_s
    # Only InService isolates the delete rejection this check tests from the transient
    # ScalingActivityInProgress that AWS returns while the attach's own scaling
    # activity is still resolving -- Pending is not enough.
    settled_states = {"InService"}
    while time.monotonic() < deadline:
        group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]
        current = {
            inst["InstanceId"]
            for inst in group["Instances"]
            if inst["LifecycleState"] in settled_states
        }
        if current == expected_ids:
            return current
        time.sleep(interval_s)
    raise AssertionError(
        f"{asg_name} membership did not settle to {expected_ids!r} within {timeout_s}s; "
        f"last observed {current!r}"
    )



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
