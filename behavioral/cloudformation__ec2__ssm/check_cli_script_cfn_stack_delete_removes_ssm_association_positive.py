"""cli-script-cfn-stack-delete-removes-ssm-association-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-script-cfn-stack-delete-removes-ssm-association-positive"
GROUP = "cli_workflows"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a CFN stack (via CLI) that owns an EC2 instance + SSM association tears down
    both: the association becomes AssociationDoesNotExist and the instance terminates."""
    require_tools("aws")

    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-cfn-assoc-")
    template = _template()
    tmpl_path = _write_temp_json(template)
    try:
        _run_aws(
            ctx,
            "cloudformation", "create-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmpl_path}",
            "--capabilities", "CAPABILITY_IAM",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path)

    # Fallback cleanup in case the in-test delete assertion fails partway.
    stack_deleted = {"done": False}

    def _delete_stack_if_needed():
        if stack_deleted["done"]:
            return
        _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60, check=False)

    ctx.on_cleanup(_delete_stack_if_needed)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
        description=f"stack {stack_name} create",
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    instance_id = next(r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Instance")
    association_id = next(r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == "Association")

    # Confirm the association exists (baseline) before tearing the stack down.
    desc = ssm.describe_association(AssociationId=association_id)
    found_id = desc["AssociationDescription"]["AssociationId"]
    assert found_id == association_id, f"expected association {association_id}, describe returned {found_id}"

    _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60)
    del_status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in (None, "DELETE_COMPLETE", "DELETE_FAILED"),
        timeout_s=300,
        interval_s=10,
        description=f"stack {stack_name} delete",
    )
    stack_deleted["done"] = True
    assert del_status in (None, "DELETE_COMPLETE"), f"stack did not delete cleanly: {del_status}"

    assoc_code, assoc_message = _error(lambda: ssm.describe_association(AssociationId=association_id))
    assert assoc_code == "AssociationDoesNotExist", (
        f"expected AssociationDoesNotExist after stack delete, got {assoc_code!r}"
    )
    assert assoc_message == f"Association {association_id} does not exist.", (
        f"DescribeAssociation on the deleted association: unexpected message {assoc_message!r}"
    )

    final_state = _poll_until(
        lambda: _instance_state(ec2, instance_id),
        lambda s: s == "terminated",
        timeout_s=180,
        interval_s=10,
        description=f"EC2 instance {instance_id} termination",
    )
    assert final_state == "terminated", f"expected instance {instance_id} terminated, still {final_state}"


def _template() -> dict:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    managed_tag = [{"Key": "sim2real:managed", "Value": "true"}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            },
        },
        "Resources": {
            # No default VPC is assumed to exist — the stack brings its own routable network so the
            # check works on a freshly provisioned account too.
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.77.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [{"Key": "Name", "Value": "sim2real-cfn-assoc-vpc"}, *managed_tag],
                },
            },
            "Igw": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {"Tags": managed_tag},
            },
            "IgwAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.77.0.0/24",
                    "MapPublicIpOnLaunch": True,
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": managed_tag,
                },
            },
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": managed_tag},
            },
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IgwAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "Igw"},
                },
            },
            "SubnetRouteAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "SsmRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
                    "Tags": managed_tag,
                },
            },
            "SsmProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "InstanceSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real assoc test sg",
                    "VpcId": {"Ref": "Vpc"},
                    "Tags": managed_tag,
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": "SubnetRouteAssoc",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmProfile"},
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "InstanceSg"}],
                    # The instance carries only a Name tag.
                    "Tags": [{"Key": "Name", "Value": "sim2real-cfn-assoc"}],
                },
            },
            "Association": {
                "Type": "AWS::SSM::Association",
                "Properties": {
                    "Name": "AWS-RunShellScript",
                    "Targets": [{"Key": "InstanceIds", "Values": [{"Ref": "Instance"}]}],
                    "Parameters": {"commands": ["echo sim2real-assoc"]},
                },
            },
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
            raise AssertionError(f"{description} not met within {timeout_s}s; last value: {value!r}")
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


def _instance_state(ec2, instance_id):
    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception:
        return None
    reservations = desc.get("Reservations", [])
    if not reservations:
        return None
    return reservations[0]["Instances"][0]["State"]["Name"]


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
