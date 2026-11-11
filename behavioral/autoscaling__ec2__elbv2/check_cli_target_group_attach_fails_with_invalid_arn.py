"""cli-target-group-attach-fails-with-invalid-arn."""
from __future__ import annotations

import json
import re
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-target-group-attach-fails-with-invalid-arn"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """attach-load-balancer-target-groups rejects a malformed target group ARN with ValidationError
    and leaves TargetGroupARNs unchanged; the same command with a real ARN succeeds."""
    require_tools("aws")

    vpc_id, subnet_ids = _shared_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-btga-")
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg")
    lt_id = _create_launch_template(ctx, name + "-lt", sg_id)
    asg_name = name + "-asg"

    _run_aws(
        ctx,
        "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", f"LaunchTemplateId={lt_id},Version=$Latest",
        "--min-size", "1", "--max-size", "1", "--desired-capacity", "1",
        "--vpc-zone-identifier", ",".join(subnet_ids),
    )
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, asg_name))

    _wait_for_instances_in_service(ctx, asg_name, 1, timeout_s=300.0)

    before = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["TargetGroupARNs"]
    assert before == [], f"expected freshly created ASG to have no target groups, got {before}"

    bad_proc = _run_shell(
        ctx,
        [
            "aws", "--output", "json",
            "autoscaling", "attach-load-balancer-target-groups",
            "--auto-scaling-group-name", asg_name,
            "--target-group-arns", "not-a-target-group-arn",
        ],
        check=False,
    )
    assert bad_proc.returncode != 0, "expected malformed target group ARN to be rejected"
    code, message = _cli_error(bad_proc.stderr)
    assert code == "ValidationError", f"expected ValidationError, got {code!r} (stderr={bad_proc.stderr[-300:]})"
    assert message == "Provided Target Groups may not be valid. Please ensure they exist and try again.", (
        f"unexpected refusal message {message!r} (stderr={bad_proc.stderr[-300:]!r})"
    )

    after_bad = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["TargetGroupARNs"]
    assert after_bad == [], f"ASG TargetGroupARNs mutated by a rejected attach call: {after_bad}"

    tg_arn = _create_target_group(ctx, name + "-tg", vpc_id)
    _run_aws(
        ctx,
        "autoscaling", "attach-load-balancer-target-groups",
        "--auto-scaling-group-name", asg_name,
        "--target-group-arns", tg_arn,
    )
    after_good = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["TargetGroupARNs"]
    assert after_good == [tg_arn], f"positive-control attach with a valid ARN did not take effect: {after_good}"


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


def _cli_error(stderr: str):
    """The (code, message) of the CLI's "An error occurred (Code) when calling ..." line."""
    match = re.search(r"An error occurred \(([A-Za-z0-9]+)\) when calling the \w+ operation: (.*)", stderr)
    return (match.group(1), match.group(2).strip()) if match else (None, None)


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _shared_vpc_and_subnets(ctx):
    """The run's shared network: its VPC and two of its subnets."""
    net = ctx.network()
    if len(net.subnet_ids) < 2:
        raise AssertionError(f"the shared network has fewer than 2 subnets: {net.subnet_ids}")
    return net.vpc_id, net.subnet_ids[:2]


def _create_security_group(ctx, vpc_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test security group",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = resp["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
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


def _create_target_group(ctx, name: str, vpc_id: str) -> str:
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
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _terminate_asg_and_wait(ctx, asg_name: str, timeout_s: float = 600.0) -> None:
    """Force-delete the ASG and wait until it is gone, so its instance releases the security group.
    An ASG already gone is done; any other failure, or the deadline, raises."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return
        time.sleep(5)
    raise AssertionError(f"ASG {asg_name} still exists {timeout_s:.0f}s after its force delete")


def _wait_for_instances_in_service(ctx, asg_name: str, expected_count: int, timeout_s: float = 300.0):
    autoscaling = ctx.client("autoscaling")

    def probe():
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"]

    return _poll_until(probe, lambda ids: len(ids) >= expected_count, timeout_s=timeout_s, interval_s=10.0)


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
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
