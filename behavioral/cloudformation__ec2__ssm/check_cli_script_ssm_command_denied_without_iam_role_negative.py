"""cli-script-ssm-command-denied-without-iam-role-negative."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-script-ssm-command-denied-without-iam-role-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two stack instances, only the one whose role grants AmazonSSMManagedInstanceCore registers
    with SSM and runs a command to Success; send-command to the other fails with InvalidInstanceId
    and the exact "Instances not in a valid state for account" message."""
    require_tools("aws")

    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    vpc_id, subnet_id = _default_vpc_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError("no shared network VPC/subnet available in this account/region")

    stack_name = ctx.unique_name("sim2real-cfn-norole-")
    template = _template(vpc_id)
    tmpl_path = _write_temp_json(template)
    try:
        _run_aws(
            ctx,
            "cloudformation", "create-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmpl_path}",
            "--parameters",
            f"ParameterKey=SubnetId,ParameterValue={subnet_id}",
            f"ParameterKey=VpcId,ParameterValue={vpc_id}",
            "--capabilities", "CAPABILITY_IAM",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path)

    def _delete_stack():
        _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60)
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s in (None, "DELETE_COMPLETE"),
            timeout_s=600,
            interval_s=10,
            description=f"delete of stack {stack_name}",
        )

    ctx.on_cleanup(_delete_stack)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
        description=f"create of stack {stack_name} reaching a terminal status",
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    good_id = outputs["GoodInstanceId"]
    bad_id = outputs["BadInstanceId"]

    # Positive control: wait for the properly-permissioned instance to register. This proves
    # network connectivity to the SSM control plane works at all in this environment.
    registered = _poll_until(
        lambda: _is_registered(ssm, good_id),
        lambda ok: ok,
        timeout_s=300,
        interval_s=15,
        description=f"control instance {good_id} SSM registration",
    )
    assert registered, f"control instance {good_id} never registered as an SSM managed instance"

    # Effect absent: the under-permissioned instance never registers, over the same window.
    assert not _is_registered(ssm, bad_id), f"instance {bad_id} unexpectedly registered without SSM permissions"

    code, message = _error(
        lambda: ssm.send_command(
            InstanceIds=[bad_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["echo should-not-run"]},
        )
    )
    assert code == "InvalidInstanceId", f"expected InvalidInstanceId denying send-command to unregistered instance {bad_id}, got {code!r}"
    assert message == "Instances not in a valid state for account", (
        f"unexpected InvalidInstanceId message: {message!r}"
    )

    # Positive control repeated at the command layer: the properly-permissioned instance
    # actually executes a command end-to-end.
    send_resp = ssm.send_command(
        InstanceIds=[good_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["echo sim2real-control-ok"]},
    )
    command_id = send_resp["Command"]["CommandId"]
    invocation = _poll_until(
        lambda: _get_invocation(ssm, command_id, good_id),
        lambda inv: inv is not None and inv["Status"] not in ("Pending", "InProgress", "Delayed"),
        timeout_s=120,
        interval_s=5,
        description=f"command {command_id} invocation on {good_id} reaching a terminal status",
    )
    assert invocation is not None and invocation["Status"] == "Success", (
        f"expected control instance {good_id} command invocation to reach Success, got {invocation!r}"
    )
    assert "sim2real-control-ok" in invocation["StandardOutputContent"], (
        f"expected 'sim2real-control-ok' in command output, got {invocation['StandardOutputContent']!r}"
    )


def _template(vpc_id: str) -> dict:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    common_props = lambda profile_ref: {
        "ImageId": {"Ref": "LatestAmiId"},
        "InstanceType": "t3.micro",
        "IamInstanceProfile": {"Ref": profile_ref},
        "SubnetId": {"Ref": "SubnetId"},
        "SecurityGroupIds": [{"Ref": "InstanceSg"}],
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetId": {"Type": "AWS::EC2::Subnet::Id"},
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            },
        },
        "Resources": {
            "GoodRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
                },
            },
            "GoodProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "GoodRole"}]},
            },
            "BadRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": trust},
            },
            "BadProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "BadRole"}]},
            },
            "InstanceSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real norole test sg", "VpcId": {"Ref": "VpcId"}},
            },
            "GoodInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    **common_props("GoodProfile"),
                    "Tags": [{"Key": "Name", "Value": "sim2real-good"}],
                },
            },
            "BadInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    **common_props("BadProfile"),
                    "Tags": [{"Key": "Name", "Value": "sim2real-bad"}],
                },
            },
        },
        "Outputs": {
            "GoodInstanceId": {"Value": {"Ref": "GoodInstance"}},
            "BadInstanceId": {"Value": {"Ref": "BadInstance"}},
        },
    }


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


def _write_temp_json(obj: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _stack_status(cfn, stack_name):
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except Exception:
        return None
    if not stacks:
        return None
    return stacks[0]["StackStatus"]


def _default_vpc_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None, None
    return vpc_id, subnets[0]["SubnetId"]


def _is_registered(ssm, instance_id) -> bool:
    resp = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    )
    return len(resp.get("InstanceInformationList", [])) > 0


def _get_invocation(ssm, command_id, instance_id):
    try:
        return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except Exception:
        return None


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, so an
    over-permissive target is reported as accepting the call, not as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected send-command to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
