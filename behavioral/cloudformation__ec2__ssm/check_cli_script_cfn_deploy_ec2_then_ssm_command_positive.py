"""cli-script-cfn-deploy-ec2-then-ssm-command-positive."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-script-cfn-deploy-ec2-then-ssm-command-positive"
GROUP = "cli_workflows"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CLI deploys a stack provisioning an EC2 instance with an SSM-capable role, then a
    subsequent CLI `ssm send-command` actually executes on that instance and returns output."""
    require_tools("aws")

    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    vpc_id, subnet_id = _default_vpc_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError("no shared network VPC/subnet available in this account/region")

    stack_name = ctx.unique_name("sim2real-cfn-ssm-")
    template = _instance_template(vpc_id)
    tmpl_path = _write_temp_json(template)
    try:
        _run_aws(
            ctx,
            "cloudformation",
            "create-stack",
            "--stack-name",
            stack_name,
            "--template-body",
            f"file://{tmpl_path}",
            "--parameters",
            f"ParameterKey=SubnetId,ParameterValue={subnet_id}",
            f"ParameterKey=VpcId,ParameterValue={vpc_id}",
            "--capabilities",
            "CAPABILITY_IAM",
            "--tags",
            "Key=sim2real:managed,Value=true",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path)

    def _delete_stack():
        _run_aws(
            ctx,
            "cloudformation",
            "delete-stack",
            "--stack-name",
            stack_name,
            timeout_s=60,
        )
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s in (None, "DELETE_COMPLETE"),
            timeout_s=600,
            interval_s=10,
        )

    ctx.on_cleanup(_delete_stack)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    instance_id = next(
        o["OutputValue"] for o in outputs if o["OutputKey"] == "InstanceId"
    )

    # SSM Agent typically registers a fresh instance as a managed instance within a few
    # minutes of boot; poll for it rather than sleeping a fixed duration.
    registered = _poll_until(
        lambda: _is_registered(ssm, instance_id),
        lambda ok: ok,
        timeout_s=300,
        interval_s=15,
    )
    assert registered, (
        f"instance {instance_id} never registered as an SSM managed instance"
    )

    send_resp = _run_aws(
        ctx,
        "ssm",
        "send-command",
        "--instance-ids",
        instance_id,
        "--document-name",
        "AWS-RunShellScript",
        "--parameters",
        json.dumps({"commands": ["echo sim2real-hello-world"]}),
        timeout_s=30,
    )
    command_id = send_resp["Command"]["CommandId"]

    invocation = _poll_until(
        lambda: _get_invocation(ssm, command_id, instance_id),
        lambda inv: (
            inv is not None
            and inv["Status"] not in ("Pending", "InProgress", "Delayed")
        ),
        timeout_s=120,
        interval_s=5,
    )
    assert invocation is not None, (
        f"command {command_id} never reached a terminal state on {instance_id}"
    )
    assert invocation["Status"] == "Success", f"unexpected status: {invocation}"
    assert "sim2real-hello-world" in invocation["StandardOutputContent"], (
        f"expected 'sim2real-hello-world' in command output, got: {invocation['StandardOutputContent']!r}"
    )


def _instance_template(vpc_id: str) -> dict:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
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
            "SsmRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                    ],
                },
            },
            "SsmProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "InstanceSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real ssm test sg",
                    "VpcId": {"Ref": "VpcId"},
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmProfile"},
                    "SubnetId": {"Ref": "SubnetId"},
                    "SecurityGroupIds": [{"Ref": "InstanceSg"}],
                    "Tags": [{"Key": "Name", "Value": "sim2real-cfn-ssm"}],
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
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
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
