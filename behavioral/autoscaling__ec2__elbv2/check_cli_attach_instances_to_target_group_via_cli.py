"""cli-attach-instances-to-target-group-via-cli."""
from __future__ import annotations

import json
import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cli-attach-instances-to-target-group-via-cli"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """aws elbv2 register-targets with raw EC2 instance IDs (no ASG involved) registers exactly
    those instances, observable via DescribeTargetHealth, and deregister-targets removes them."""
    require_tools("aws")

    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-regtgt-")
    sg_id = _create_security_group(ctx, vpc_id, name + "-sg")

    ec2 = ctx.client("ec2")
    run_resp = ec2.run_instances(
        ImageId="resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
        InstanceType="t3.micro",
        MinCount=2,
        MaxCount=2,
        SubnetId=subnet_ids[0],
        SecurityGroupIds=[sg_id],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
    ctx.on_cleanup(lambda: _terminate_instances_and_wait(ctx, instance_ids))

    ec2.get_waiter("instance_running").wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    tg_arn = _create_target_group(ctx, name + "-tg", vpc_id)

    _run_aws(
        ctx,
        "elbv2", "register-targets",
        "--target-group-arn", tg_arn,
        "--targets", f"Id={instance_ids[0]}", f"Id={instance_ids[1]}",
    )

    registered = _wait_for_registered_target_ids(ctx, tg_arn, instance_ids, timeout_s=120.0)
    assert registered == set(instance_ids), (
        f"expected target group to register {set(instance_ids)}, got {registered}"
    )

    _run_aws(
        ctx,
        "elbv2", "deregister-targets",
        "--target-group-arn", tg_arn,
        "--targets", f"Id={instance_ids[0]}", f"Id={instance_ids[1]}",
    )
    _wait_for_absent_target_ids(ctx, tg_arn, instance_ids, timeout_s=120.0)


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
            "EC2/ELB test infrastructure"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets; cannot provision EC2/ELB test infrastructure")
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
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}],
    )
    return tg_arn


def _terminate_instances_and_wait(ctx, instance_ids, timeout_s: float = 240.0) -> None:
    """Terminate the instances and wait for terminated; instances already gone are done,
    anything else raises."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


def _wait_for_registered_target_ids(ctx, tg_arn: str, expected_ids, timeout_s: float = 180.0):
    elbv2 = ctx.client("elbv2")
    expected = set(expected_ids)

    def probe():
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return {d["Target"]["Id"] for d in descs}

    return _poll_until(probe, lambda ids: expected.issubset(ids), timeout_s=timeout_s, interval_s=8.0)


def _wait_for_absent_target_ids(ctx, tg_arn: str, target_ids, timeout_s: float = 120.0, interval_s: float = 5.0):
    elbv2 = ctx.client("elbv2")
    excluded = set(target_ids)
    deadline = time.monotonic() + timeout_s
    remaining = excluded
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        registered = {d["Target"]["Id"] for d in descs}
        remaining = excluded & registered
        if not remaining:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"expected deregister-targets to remove {excluded} from {tg_arn}, still registered: {remaining}"
    )



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
