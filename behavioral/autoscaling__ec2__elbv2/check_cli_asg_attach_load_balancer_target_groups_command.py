"""cli-asg-attach-load-balancer-target-groups-command."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-asg-attach-load-balancer-target-groups-command"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ec2", "elbv2"]

# One retry deadline shared by every teardown step of this check:
# a force-deleted group drains its target-group registrations before its instances terminate.
_TEARDOWN_RETRY_S = 1800.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """attach-load-balancer-target-groups on a running ASG both (a) adds the ARN to the ASG's
    TargetGroupARNs list and (b) retroactively registers the ASG's existing instances with the
    newly attached target group."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    require_tools("aws")

    name = ctx.unique_name("sim2real-atg-")
    network = ctx.network()
    vpc_id, subnet_ids = network.vpc_id, network.subnet_ids[:2]
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg", teardown_deadline)
    lt_id = _create_launch_template(ctx, name + "-lt", sg_id)
    tg_arn = _create_target_group(ctx, name + "-tg", vpc_id, teardown_deadline)
    asg_name = name + "-asg"

    _run_aws(
        ctx,
        "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", f"LaunchTemplateId={lt_id},Version=$Latest",
        "--min-size", "1", "--max-size", "1", "--desired-capacity", "1",
        "--vpc-zone-identifier", ",".join(subnet_ids),
    )
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, asg_name, teardown_deadline))

    instance_ids = _wait_for_instances_in_service(ctx, asg_name, 1, timeout_s=300.0)
    assert len(instance_ids) == 1, f"expected exactly 1 InService instance, got {instance_ids}"

    before = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["TargetGroupARNs"]
    assert tg_arn not in before, f"expected {tg_arn} absent from ASG TargetGroupARNs before attach, got {before}"

    _run_aws(
        ctx,
        "autoscaling", "attach-load-balancer-target-groups",
        "--auto-scaling-group-name", asg_name,
        "--target-group-arns", tg_arn,
    )

    after = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["TargetGroupARNs"]
    assert tg_arn in after, f"expected {tg_arn} in ASG TargetGroupARNs, got {after}"

    registered = _wait_for_registered_target_ids(ctx, tg_arn, instance_ids, timeout_s=120.0)
    assert registered == set(instance_ids), (
        f"attach did not retroactively register existing instances: {registered} != {set(instance_ids)}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _create_security_group(ctx, vpc_id: str, name: str, teardown_deadline) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test security group",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id, teardown_deadline))
    return sg_id


def _create_launch_template(ctx, name: str, sg_id: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            "InstanceType": "t3.micro",
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        },
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_target_group(ctx, name: str, vpc_id: str, teardown_deadline) -> str:
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckIntervalSeconds=10,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
    )
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn, teardown_deadline))
    return tg_arn


def _terminate_asg_and_wait(ctx, asg_name: str, teardown_deadline) -> None:
    """Force-delete the group and wait until it is gone: a refusal while a scaling activity runs
    is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
            if err["Code"] not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"auto scaling group {asg_name} still listed at the teardown deadline")
        time.sleep(2)


def _wait_for_instances_in_service(ctx, asg_name: str, expected_count: int, timeout_s: float = 300.0):
    autoscaling = ctx.client("autoscaling")

    def probe():
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"]

    return _poll_until(probe, lambda ids: len(ids) >= expected_count, timeout_s=timeout_s, interval_s=10.0)


def _wait_for_registered_target_ids(ctx, tg_arn: str, expected_ids, timeout_s: float = 180.0):
    elbv2 = ctx.client("elbv2")
    expected = set(expected_ids)

    def probe():
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return {d["Target"]["Id"] for d in descs}

    return _poll_until(probe, lambda ids: expected.issubset(ids), timeout_s=timeout_s, interval_s=8.0)


def _delete_security_group_when_free(ec2, sg_id, teardown_deadline, interval_s=2.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_target_group_when_free(elbv2, arn, teardown_deadline, interval_s=2.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
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
