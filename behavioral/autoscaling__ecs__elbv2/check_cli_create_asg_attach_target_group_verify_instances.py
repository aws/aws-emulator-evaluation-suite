"""cli-create-asg-attach-target-group-verify-instances."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags

CHECK = "cli-create-asg-attach-target-group-verify-instances"
GROUP = "cli-workflow"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A shell script drives the AWS CLI to create an Auto Scaling group and attach
    an instance-type target group to it; the SDK then verifies that the exact
    instance IDs launched by the ASG show up as registered targets in elbv2."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_web_sg(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id, user_data_script=_HTTPD_USER_DATA)
    tg_arn = _create_target_group(ctx, vpc_id)

    asg_name = ctx.unique_name("sim2real-asg-")
    _run_aws(
        ctx, "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", json.dumps({"LaunchTemplateId": lt_id, "Version": "$Latest"}),
        "--min-size", "1", "--max-size", "1", "--desired-capacity", "1",
        "--vpc-zone-identifier", ",".join(subnet_ids),
        "--health-check-type", "EC2", "--health-check-grace-period", "90",
    )
    _register_asg_cleanup(ctx, asg_name)

    instance_ids = _wait_for_asg_instance_ids(ctx, asg_name, count=1, timeout_s=300)

    _run_aws(
        ctx, "autoscaling", "attach-load-balancer-target-groups",
        "--auto-scaling-group-name", asg_name, "--target-group-arns", tg_arn,
    )

    # the CLI attach call is also reflected back through the ASG's own view of its
    # attached load balancer target groups (not just the elbv2 side) -- checked first
    # so the terminal read stays on elbv2, the consumer of the attachment, not the
    # autoscaling producer that issued it
    asg_client = ctx.client("autoscaling")
    attached = asg_client.describe_load_balancer_target_groups(AutoScalingGroupName=asg_name)[
        "LoadBalancerTargetGroups"
    ]
    assert any(g["LoadBalancerTargetGroupARN"] == tg_arn for g in attached), (
        f"expected {tg_arn} in ASG's own attached target groups, got {attached}"
    )

    descs = _wait_for_target_ids(ctx, tg_arn, instance_ids, timeout_s=300)
    seen_ids = {d["Target"]["Id"] for d in descs}
    assert seen_ids == set(instance_ids), f"expected targets {instance_ids}, got {seen_ids}"


_HTTPD_USER_DATA = "#!/bin/bash\nyum install -y httpd\nsystemctl enable httpd\nsystemctl start httpd\n"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True, text=True,
        timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=60.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for ASG test instances")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for ASG test instances")
    return vpc_id, [s["SubnetId"] for s in subnets]


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_web_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real behavioral test sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]

    def _cleanup():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, user_data_script=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-lt-")
    lt_data = {"ImageId": ami_id, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]}
    if user_data_script:
        lt_data["UserData"] = base64.b64encode(user_data_script.encode()).decode()
    lt_id = ec2.create_launch_template(LaunchTemplateName=name, LaunchTemplateData=lt_data)["LaunchTemplate"][
        "LaunchTemplateId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_target_group(ctx, vpc_id, port=80):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-asgtg-tg-")
    tg = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPort="traffic-port", HealthCheckPath="/",
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, HealthCheckIntervalSeconds=10,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _register_asg_cleanup(ctx, name):
    asg = ctx.client("autoscaling")

    def _cleanup():
        from botocore.exceptions import ClientError

        busy = ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse")
        try:
            asg.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            if err["Code"] not in busy:
                raise
        # ForceDelete terminates the instances itself; retry while a scaling activity holds the group,
        # then poll until the group is gone. One 960 s deadline covers both.
        deadline = time.monotonic() + 960
        while True:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                break
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                    return
                if err["Code"] not in busy or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        while time.monotonic() < deadline:
            resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])
            if not resp["AutoScalingGroups"]:
                return
            time.sleep(2)
        raise AssertionError(f"ASG {name} still listed at its 960 s teardown deadline")

    ctx.on_cleanup(_cleanup)


def _wait_for_asg_instance_ids(ctx, asg_name, count, timeout_s=300.0):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if resp:
            last = resp[0]["Instances"]
            if len(last) >= count:
                return [i["InstanceId"] for i in last]
        time.sleep(2)
    raise AssertionError(f"ASG {asg_name} never reached {count} instances (last={last})")


def _wait_for_target_ids(ctx, tg_arn, expected_ids, timeout_s=300.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    seen: set[str] = set()
    descs = []
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        seen = {d["Target"]["Id"] for d in descs}
        if set(expected_ids).issubset(seen):
            return descs
        time.sleep(2)
    raise AssertionError(f"target group {tg_arn} never registered {expected_ids}; saw {seen}")



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
