"""cli-describe-target-health-reflects-asg-instances."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-describe-target-health-reflects-asg-instances"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """aws elbv2 describe-target-health, run through the CLI, reports exactly the set of EC2
    instance IDs that the ASG (queried independently via the autoscaling SDK) currently manages
    behind that target group."""
    require_tools("aws")

    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-tgh-")
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg")
    lt_id = _create_launch_template(ctx, name + "-lt", sg_id)
    tg_arn = _create_target_group(ctx, name + "-tg", vpc_id)
    asg_name = name + "-asg"

    _run_aws(
        ctx,
        "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", f"LaunchTemplateId={lt_id},Version=$Latest",
        "--min-size", "2", "--max-size", "2", "--desired-capacity", "2",
        "--vpc-zone-identifier", ",".join(subnet_ids),
        "--target-group-arns", tg_arn,
    )
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, asg_name))

    instance_ids = _wait_for_instances_in_service(ctx, asg_name, 2, timeout_s=300.0)
    assert len(instance_ids) == 2, f"expected 2 InService instances, got {instance_ids}"
    _wait_for_registered_target_ids(ctx, tg_arn, instance_ids, timeout_s=120.0)

    cli_output = _run_aws(ctx, "elbv2", "describe-target-health", "--target-group-arn", tg_arn)
    cli_target_ids = {d["Target"]["Id"] for d in cli_output["TargetHealthDescriptions"]}

    asg_group = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]
    asg_instance_ids = {i["InstanceId"] for i in asg_group["Instances"]}

    assert cli_target_ids == asg_instance_ids, (
        f"CLI describe-target-health ({cli_target_ids}) does not match ASG instance set "
        f"({asg_instance_ids})"
    )

    _delete_target_group_and_assert_gone(ctx, tg_arn)
    _terminate_asg_and_wait(ctx, asg_name)
    remaining = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    assert remaining == [], f"expected ASG {asg_name} to be gone after delete, still present: {remaining}"


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


def _get_default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; cannot discover subnets to provision "
            "ASG/ELB test infrastructure"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets; cannot provision ASG/ELB test infrastructure")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    return vpc_id, subnet_ids


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
    ctx.on_cleanup(lambda: _delete_target_group_ignore_missing(ctx, tg_arn))
    return tg_arn


def _delete_target_group_ignore_missing(ctx, tg_arn: str) -> None:
    from botocore.exceptions import ClientError

    elbv2 = ctx.client("elbv2")
    try:
        _delete_target_group_when_free(elbv2, tg_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _delete_target_group_and_assert_gone(ctx, tg_arn: str) -> None:
    from botocore.exceptions import ClientError

    elbv2 = ctx.client("elbv2")
    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    try:
        elbv2.describe_target_health(TargetGroupArn=tg_arn)
        raise AssertionError(
            f"expected TargetGroupNotFound after delete_target_group({tg_arn}), but "
            f"describe_target_health succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "TargetGroupNotFound", (
            f"expected TargetGroupNotFound after delete_target_group({tg_arn}), got {code}"
        )
        message = exc.response["Error"].get("Message", "")
        expected_message = f"Target groups '{tg_arn}' not found"
        assert message == expected_message, (
            f"TargetGroupNotFound message {message!r}, expected {expected_message!r}"
        )


def _terminate_asg_and_wait(ctx, asg_name: str, timeout_s: float = 240.0) -> None:
    """Force-delete the group and wait until it is gone: a refusal while a scaling activity runs
    is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
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
