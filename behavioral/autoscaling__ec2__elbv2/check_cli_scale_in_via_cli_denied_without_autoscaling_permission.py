"""cli-scale-in-via-cli-denied-without-autoscaling-permission."""
from __future__ import annotations

import json
import re
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-scale-in-via-cli-denied-without-autoscaling-permission"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup from a role with no permissions is denied and leaves the instance
    count unchanged; the same scale-in with full permissions lowers the instance count."""
    require_tools("aws")

    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-denyscale-")
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg")
    lt_id = _create_launch_template(ctx, name + "-lt", sg_id)
    asg_name = name + "-asg"

    _run_aws(
        ctx,
        "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", f"LaunchTemplateId={lt_id},Version=$Latest",
        "--min-size", "1", "--max-size", "3", "--desired-capacity", "2",
        "--vpc-zone-identifier", ",".join(subnet_ids),
    )
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, asg_name))

    _wait_for_instances_in_service(ctx, asg_name, 2, timeout_s=300.0)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-noperm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    creds = _assume_role_with_retry(ctx, role_arn, timeout_s=60.0)

    desired_before = _get_desired_capacity(ctx, asg_name)

    denied_proc = _run_shell(
        ctx,
        [
            "aws", "--output", "json",
            "autoscaling", "update-auto-scaling-group",
            "--auto-scaling-group-name", asg_name,
            "--desired-capacity", "1",
        ],
        env_extra={
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
        },
        check=False,
    )
    assert denied_proc.returncode != 0, "expected denied call to fail, it succeeded"
    code = _cli_error_code(denied_proc.stderr)
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r} (stderr={denied_proc.stderr[-300:]})"

    desired_after_denied = _get_desired_capacity(ctx, asg_name)
    assert desired_after_denied == desired_before, (
        "desired capacity changed despite the denied call "
        f"({desired_before} -> {desired_after_denied})"
    )

    _run_aws(
        ctx,
        "autoscaling", "update-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--desired-capacity", "1",
    )
    final_ids = _wait_for_exact_instance_count(ctx, asg_name, 1, timeout_s=300.0)
    assert len(final_ids) == 1, f"positive control scale-in did not take effect, got {final_ids}"


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


def _cli_error_code(stderr: str):
    match = re.search(r"An error occurred \(([A-Za-z0-9]+)\)", stderr)
    return match.group(1) if match else None


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
            "ASG test infrastructure"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets; cannot provision ASG test infrastructure")
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


def _wait_for_exact_instance_count(ctx, asg_name: str, expected_count: int, timeout_s: float = 300.0):
    autoscaling = ctx.client("autoscaling")

    def probe():
        groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"]]

    return _poll_until(probe, lambda ids: len(ids) == expected_count, timeout_s=timeout_s, interval_s=10.0)


def _get_desired_capacity(ctx, asg_name: str) -> int:
    groups = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    return groups[0]["DesiredCapacity"]


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behavioral-test")
            return resp["Credentials"]
        except Exception as exc:  # noqa: BLE001 - retry until trust policy propagates
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            aws_code = e.response["Error"]["Code"]
            if aws_code == "InvalidGroup.NotFound":
                return
            if aws_code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
