"""sdk-ssm-encrypted-parameter-used-in-ec2-launch-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sdk-ssm-encrypted-parameter-used-in-ec2-launch-positive"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecureString parameter reads back as plaintext only with WithDecryption=True; without it the
    value differs from the secret. The decrypted value placed in an EC2 instance's UserData is the
    exact content the instance wrote to disk, read back with a successful SSM Run Command."""
    ssm = ctx.client("ssm")
    param_name = ctx.unique_name("/sim2real/secret-")
    secret_value = ctx.unique_name("sim2real-secret-value-")
    ssm.put_parameter(Name=param_name, Value=secret_value, Type="SecureString")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    decrypted = ssm.get_parameter(Name=param_name, WithDecryption=True)["Parameter"]
    assert decrypted["Value"] == secret_value, (
        f"decrypted SecureString mismatch: expected {secret_value!r}, got {decrypted['Value']!r}"
    )

    ciphertext = ssm.get_parameter(Name=param_name, WithDecryption=False)["Parameter"]
    assert ciphertext["Value"] != secret_value, "SecureString value was not encrypted at rest"

    instance_profile = _ssm_instance_profile(ctx)
    ami_id = _latest_al2023_ami(ctx)
    user_data = f"#!/bin/bash\necho '{secret_value}' > /tmp/decrypted-secret.txt\n"
    instance_id = _launch_instance(
        ctx, ami_id, instance_profile_name=instance_profile, name_suffix="encparam", user_data=user_data
    )

    info = _wait_ssm_online(ctx, instance_id, timeout_s=300.0)
    if info is None:
        raise AssertionError(f"instance {instance_id} never registered Online with SSM")

    send = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["cat /tmp/decrypted-secret.txt"]},
        TimeoutSeconds=120,
    )
    result = _poll_invocation(ctx, send["Command"]["CommandId"], instance_id, timeout_s=180.0)
    assert result["Status"] == "Success", (
        f"run-command invocation did not succeed: status={result['Status']!r}, "
        f"stderr={result.get('StandardErrorContent', '')!r}"
    )
    actual_output = result["StandardOutputContent"].strip()
    assert actual_output == secret_value, (
        f"instance disk content mismatch: expected decrypted secret {secret_value!r}, "
        f"got {actual_output!r} written by UserData"
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


def _launch_instance(
    ctx,
    ami_id: str,
    instance_profile_name: str | None = None,
    name_suffix: str = "instance",
    user_data: str | None = None,
):
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
    if user_data:
        kwargs["UserData"] = user_data
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
