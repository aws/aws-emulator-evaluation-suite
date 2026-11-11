"""sdk-ssm-list-command-invocations-scoped-to-ec2-instance-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sdk-ssm-list-command-invocations-scoped-to-ec2-instance-positive"
GROUP = "data-format"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single SendCommand fanned out to two EC2 instances creates one CommandId with two
    per-instance invocations; list_command_invocations filtered by InstanceId returns
    exactly the invocation for that instance and none of the sibling instance's."""
    instance_profile = _ssm_instance_profile(ctx)
    ami_id = _latest_al2023_ami(ctx)
    instance_a = _launch_instance(ctx, ami_id, instance_profile_name=instance_profile, name_suffix="listinv-a")
    instance_b = _launch_instance(ctx, ami_id, instance_profile_name=instance_profile, name_suffix="listinv-b")

    info_a = _wait_ssm_online(ctx, instance_a, timeout_s=300.0)
    info_b = _wait_ssm_online(ctx, instance_b, timeout_s=300.0)
    assert info_a is not None, f"instance {instance_a} never registered Online with SSM"
    assert info_b is not None, f"instance {instance_b} never registered Online with SSM"

    ssm = ctx.client("ssm")
    send = ssm.send_command(
        InstanceIds=[instance_a, instance_b],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["echo fanout-ok"]},
        TimeoutSeconds=120,
    )
    command_id = send["Command"]["CommandId"]

    result_a = _poll_invocation(ctx, command_id, instance_a, timeout_s=180.0)
    result_b = _poll_invocation(ctx, command_id, instance_b, timeout_s=180.0)
    assert result_a["Status"] == "Success", f"expected Success on {instance_a}, got {result_a['Status']!r}"
    assert result_b["Status"] == "Success", f"expected Success on {instance_b}, got {result_b['Status']!r}"

    scoped_a = ssm.list_command_invocations(CommandId=command_id, InstanceId=instance_a)["CommandInvocations"]
    assert len(scoped_a) == 1, f"expected exactly 1 invocation scoped to {instance_a}, got {len(scoped_a)}"
    assert scoped_a[0]["InstanceId"] == instance_a, (
        f"expected scoped invocation InstanceId {instance_a}, got {scoped_a[0]['InstanceId']!r}"
    )
    assert all(inv["InstanceId"] != instance_b for inv in scoped_a), (
        f"invocation for sibling instance {instance_b} leaked into the {instance_a}-scoped list"
    )

    scoped_b = ssm.list_command_invocations(CommandId=command_id, InstanceId=instance_b)["CommandInvocations"]
    assert len(scoped_b) == 1, f"expected exactly 1 invocation scoped to {instance_b}, got {len(scoped_b)}"
    assert scoped_b[0]["InstanceId"] == instance_b, (
        f"expected scoped invocation InstanceId {instance_b}, got {scoped_b[0]['InstanceId']!r}"
    )
    assert all(inv["InstanceId"] != instance_a for inv in scoped_b), (
        f"invocation for sibling instance {instance_a} leaked into the {instance_b}-scoped list"
    )


def _tag_spec(ctx, resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a test EC2 instance")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return subnets[0]["SubnetId"]


def _ssm_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except Exception:
            time.sleep(2.0)
    return profile_name


def _launch_instance(ctx, ami_id: str, instance_profile_name: str | None = None, name_suffix: str = "instance"):
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    kwargs = dict(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name(f"sim2real-{name_suffix}-")),
    )
    if instance_profile_name:
        kwargs["IamInstanceProfile"] = {"Name": instance_profile_name}
    # A freshly created IAM instance profile can take longer to propagate to the EC2
    # control plane than to IAM itself; retry RunInstances on that specific error.
    deadline = time.monotonic() + 60.0
    resp = None
    while True:
        try:
            resp = ec2.run_instances(**kwargs)
            break
        except Exception as exc:
            if instance_profile_name and "InvalidParameterValue" in str(exc) and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _wait_ssm_online(ctx, instance_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        items = resp.get("InstanceInformationList", [])
        if items and items[0].get("PingStatus") == "Online":
            return items[0]
        time.sleep(interval_s)
    return None


def _poll_invocation(ctx, command_id: str, instance_id: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    ssm = ctx.client("ssm")
    terminal = {"Success", "Cancelled", "TimedOut", "Failed"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(interval_s)
            continue
        if last["Status"] in terminal:
            return last
        time.sleep(interval_s)
    if last is None:
        raise AssertionError("command invocation never appeared on the target instance")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
