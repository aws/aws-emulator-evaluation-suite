"""cli-attach-target-group-wrong-region-fails."""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
import time

from behavioral_harness import tags

CHECK = "cli-attach-target-group-wrong-region-fails"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]

# One teardown deadline shared by every teardown of a run: a force-deleted group drains its
# target-group registrations before its instances terminate.
_TEARDOWN_RETRY_S = 1800.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """attach-load-balancer-target-groups rejects a target group ARN from another region with
    ValidationError and registers nothing; a same-region target group registers the instance."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    # any real region other than ctx.region; this literal is the check's subject (a syntactically
    # valid ARN whose embedded region must differ from the ASG's own), not a pin on where clients operate
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_wrong_region_tg_arn = (
        f"arn:aws:elasticloadbalancing:{other_region}:{account_id}:targetgroup/sim2real-fake-tg/0123456789abcdef"
    )

    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_web_sg(ctx, vpc_id, teardown_deadline)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id, user_data_script=_HTTPD_USER_DATA)
    real_tg_arn = _create_target_group(ctx, vpc_id)

    asg_name = ctx.unique_name("sim2real-asg-")
    _run_aws(
        ctx, "autoscaling", "create-auto-scaling-group",
        "--auto-scaling-group-name", asg_name,
        "--launch-template", json.dumps({"LaunchTemplateId": lt_id, "Version": "$Latest"}),
        "--min-size", "1", "--max-size", "1", "--desired-capacity", "1",
        "--vpc-zone-identifier", ",".join(subnet_ids),
        "--health-check-type", "EC2", "--health-check-grace-period", "90",
    )
    _register_asg_cleanup(ctx, asg_name, teardown_deadline)
    instance_ids = _wait_for_asg_instance_ids(ctx, asg_name, count=1, timeout_s=300)

    proc = _run_aws_allow_failure(
        ctx, "autoscaling", "attach-load-balancer-target-groups",
        "--auto-scaling-group-name", asg_name, "--target-group-arns", fake_wrong_region_tg_arn,
    )
    assert proc.returncode != 0, "attaching a cross-region target group ARN unexpectedly succeeded"
    code = _cli_error_code(proc.stderr)
    assert code == "ValidationError", f"expected ValidationError, got {code!r} (stderr={proc.stderr[-300:]!r})"

    # effect absent: the ASG has no attached target groups at all after the rejected call
    asg_client = ctx.client("autoscaling")
    attached = asg_client.describe_load_balancer_target_groups(AutoScalingGroupName=asg_name)[
        "LoadBalancerTargetGroups"
    ]
    assert attached == [], f"ASG unexpectedly has attached target groups after rejected attach: {attached}"

    # positive control: attaching a real, same-region target group via the same CLI path succeeds
    _run_aws(
        ctx, "autoscaling", "attach-load-balancer-target-groups",
        "--auto-scaling-group-name", asg_name, "--target-group-arns", real_tg_arn,
    )
    descs = _wait_for_target_ids(ctx, real_tg_arn, instance_ids, timeout_s=300)
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


def _run_aws_allow_failure(ctx, *args: str, timeout_s=60.0):
    return _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=False)


def _cli_error_code(stderr: str):
    m = re.search(r"An error occurred \((\w+)\)", stderr)
    return m.group(1) if m else None


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


def _create_web_sg(ctx, vpc_id, teardown_deadline):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real behavioral test sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]

    def _cleanup():
        # Instance ENIs keep the group referenced (DependencyViolation) until they detach.
        from botocore.exceptions import ClientError

        deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                aws_code = exc.response["Error"]["Code"]
                if aws_code == "InvalidGroup.NotFound":
                    return
                if aws_code != "DependencyViolation" or time.monotonic() >= deadline:
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


def _register_asg_cleanup(ctx, name, teardown_deadline):
    asg = ctx.client("autoscaling")

    def _cleanup():
        """Force-delete the group and wait until it is gone: a refusal while a scaling activity
        runs is retried every 2 s, a group already gone is done, anything else raises."""
        from botocore.exceptions import ClientError

        deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
        while True:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                break
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                    return
                busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
                if err["Code"] not in busy or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        while asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"auto scaling group {name} still listed at the teardown deadline")
            time.sleep(2)

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
            aws_code = e.response["Error"]["Code"]
            if aws_code == "TargetGroupNotFound":
                return
            if aws_code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
