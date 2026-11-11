"""cli-script-cfn-update-stack-security-group-blocks-ssm-negative."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-script-cfn-update-stack-security-group-blocks-ssm-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a CLI `update-stack` drops outbound 443 from the target instance's security group, the
    restarted target stays off SSM and a Run Command to it is refused or ends DeliveryTimedOut with no
    output, while the control succeeds; restoring the egress rule makes the same command succeed."""
    require_tools("aws")

    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-cfn-sgblock-")
    initial_template = _template(restrict_target_egress=False)
    tmpl_path = _write_temp_json(initial_template)
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

    def _delete_stack():
        _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60)
        final_status = _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s in (None, "DELETE_COMPLETE"),
            timeout_s=600,
            interval_s=10,
        )
        assert final_status in (None, "DELETE_COMPLETE"), (
            f"stack {stack_name} did not tear down: {final_status}"
        )

    ctx.on_cleanup(_delete_stack)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    control_id = outputs["ControlInstanceId"]
    target_id = outputs["TargetInstanceId"]

    for iid in (control_id, target_id):
        ok = _poll_until(
            lambda iid=iid: _is_registered(ssm, iid),
            lambda ok: ok,
            timeout_s=300,
            interval_s=15,
        )
        assert ok, f"instance {iid} never registered as an SSM managed instance"

    # Break exactly one thing: rewrite the target instance's security group egress to only
    # allow port 22, dropping the outbound 443 the SSM Agent needs. The control instance's
    # security group is untouched.
    updated_template = _template(restrict_target_egress=True)
    tmpl_path2 = _write_temp_json(updated_template)
    try:
        _run_aws(
            ctx,
            "cloudformation", "update-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmpl_path2}",
            "--capabilities", "CAPABILITY_IAM",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path2)

    upd_status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert upd_status == "UPDATE_COMPLETE", f"stack update did not complete: {upd_status}"

    # A live SSM Agent session is a long-lived persistent connection; a security-group rule
    # change alone does not tear down an already-established outbound flow. Power-cycle the
    # target so its agent must open a *fresh* connection under the restricted egress —
    # that new connection attempt is what the missing outbound 443 actually blocks.
    ec2.stop_instances(InstanceIds=[target_id])
    _poll_until(
        lambda: _instance_state(ec2, target_id),
        lambda s: s == "stopped",
        timeout_s=180,
        interval_s=10,
    )
    ec2.start_instances(InstanceIds=[target_id])
    _poll_until(
        lambda: _instance_state(ec2, target_id),
        lambda s: s == "running",
        timeout_s=180,
        interval_s=10,
    )

    # Give the target a full window to attempt to reconnect; with outbound 443 blocked it
    # must never reach "Online" again.
    ping_after_restart = _poll_until(
        lambda: _ping_status(ssm, target_id),
        lambda s: s == "Online",
        timeout_s=240,
        interval_s=15,
    )
    assert ping_after_restart != "Online", (
        f"target unexpectedly reconnected to SSM after outbound 443 was removed: {ping_after_restart}"
    )

    # Control instance's security group was never touched; it remains reachable end-to-end.
    control_send = ssm.send_command(
        InstanceIds=[control_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["echo sim2real-control-still-ok"], "executionTimeout": ["30"]},
        TimeoutSeconds=30,
    )
    control_command_id = control_send["Command"]["CommandId"]
    control_invocation = _poll_until(
        lambda: _get_invocation(ssm, control_command_id, control_id),
        lambda inv: inv is not None and inv["Status"] not in ("Pending", "InProgress", "Delayed"),
        timeout_s=120,
        interval_s=5,
    )
    assert control_invocation is not None, "control command never reached a terminal invocation status"
    assert control_invocation["Status"] == "Success", f"unexpected: {control_invocation}"
    assert "sim2real-control-still-ok" in control_invocation["StandardOutputContent"], (
        f"control output missing expected marker: {control_invocation['StandardOutputContent']!r}"
    )

    # Attempting to deliver a command to the disconnected target must not succeed: either the
    # send is rejected outright, or the command is accepted but never delivered (terminal
    # non-Success status, no output ever recorded).
    from botocore.exceptions import ClientError

    doc_params = {"commands": ["echo should-not-be-delivered"], "executionTimeout": ["30"]}
    target_command_id = None
    send_error_code = None
    send_error_message = None
    try:
        target_send = ssm.send_command(
            InstanceIds=[target_id],
            DocumentName="AWS-RunShellScript",
            Parameters=doc_params,
            TimeoutSeconds=30,
        )
        target_command_id = target_send["Command"]["CommandId"]
    except ClientError as err:
        send_error_code = err.response["Error"]["Code"]
        send_error_message = err.response["Error"].get("Message")

    if send_error_code is not None:
        assert send_error_code == "InvalidInstanceId", f"unexpected error: {send_error_code}"
        expected_message = (
            "Instances not in a valid state for account"
        )
        assert send_error_message == expected_message, (
            f"unexpected InvalidInstanceId message: {send_error_message!r}"
        )
    else:
        target_invocation = _poll_until(
            lambda: _get_invocation(ssm, target_command_id, target_id),
            lambda inv: inv is not None and inv["Status"] not in ("Pending", "InProgress", "Delayed"),
            timeout_s=120,
            interval_s=5,
        )
        assert target_invocation is not None, "target command never reached a terminal invocation status"
        assert target_invocation["Status"] != "Success", f"unexpected: {target_invocation}"
        assert target_invocation.get("StatusDetails") == "DeliveryTimedOut", (
            f"expected StatusDetails=DeliveryTimedOut, got: {target_invocation}"
        )
        assert target_invocation["StandardOutputContent"] == "", (
            f"expected no output ever recorded, got: {target_invocation['StandardOutputContent']!r}"
        )

    # Restore the one thing that was broken: put the target's security group back to unrestricted
    # egress, and demand the identical call succeeds — a security-group rule is reversible, so
    # the negative is not complete without proving the block was the cause and not a fluke.
    restored_template = _template(restrict_target_egress=False)
    tmpl_path3 = _write_temp_json(restored_template)
    try:
        _run_aws(
            ctx,
            "cloudformation", "update-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmpl_path3}",
            "--capabilities", "CAPABILITY_IAM",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path3)

    restore_status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert restore_status == "UPDATE_COMPLETE", f"restore update did not complete: {restore_status}"

    ec2.stop_instances(InstanceIds=[target_id])
    _poll_until(
        lambda: _instance_state(ec2, target_id),
        lambda s: s == "stopped",
        timeout_s=180,
        interval_s=10,
    )
    ec2.start_instances(InstanceIds=[target_id])
    _poll_until(
        lambda: _instance_state(ec2, target_id),
        lambda s: s == "running",
        timeout_s=180,
        interval_s=10,
    )

    ping_after_restore = _poll_until(
        lambda: _ping_status(ssm, target_id),
        lambda s: s == "Online",
        timeout_s=300,
        interval_s=15,
    )
    assert ping_after_restore == "Online", (
        f"target never reconnected to SSM after outbound 443 was restored: {ping_after_restore}"
    )

    restored_send = ssm.send_command(
        InstanceIds=[target_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["echo sim2real-target-restored-ok"], "executionTimeout": ["30"]},
        TimeoutSeconds=30,
    )
    restored_command_id = restored_send["Command"]["CommandId"]
    restored_invocation = _poll_until(
        lambda: _get_invocation(ssm, restored_command_id, target_id),
        lambda inv: inv is not None and inv["Status"] not in ("Pending", "InProgress", "Delayed"),
        timeout_s=120,
        interval_s=5,
    )
    assert restored_invocation is not None, "restored target command never reached a terminal status"
    assert restored_invocation["Status"] == "Success", f"unexpected: {restored_invocation}"
    assert "sim2real-target-restored-ok" in restored_invocation["StandardOutputContent"], (
        f"restored target output missing expected marker: {restored_invocation['StandardOutputContent']!r}"
    )


def _template(restrict_target_egress: bool) -> dict:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            },
        },
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "Igw": {"Type": "AWS::EC2::InternetGateway"},
            "IgwAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
            "Route": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IgwAttach",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "Igw"},
                },
            },
            "SubnetRouteTableAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "SsmRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
                },
            },
            "SsmProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "ControlSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real sgblock control sg",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}],
                },
            },
            "TargetSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real sgblock target sg",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupEgress": (
                        [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]
                        if restrict_target_egress
                        else [{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}]
                    ),
                },
            },
            "ControlInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmProfile"},
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "ControlSg"}],
                    "Tags": [{"Key": "Name", "Value": "sim2real-sgblock-control"}],
                },
            },
            "TargetInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmProfile"},
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "TargetSg"}],
                    "Tags": [{"Key": "Name", "Value": "sim2real-sgblock-target"}],
                },
            },
        },
        "Outputs": {
            "ControlInstanceId": {"Value": {"Ref": "ControlInstance"}},
            "TargetInstanceId": {"Value": {"Ref": "TargetInstance"}},
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


def _is_registered(ssm, instance_id) -> bool:
    resp = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    )
    return len(resp.get("InstanceInformationList", [])) > 0


def _ping_status(ssm, instance_id):
    resp = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    )
    infos = resp.get("InstanceInformationList", [])
    if not infos:
        return None
    return infos[0].get("PingStatus")


def _instance_state(ec2, instance_id):
    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception:
        return None
    reservations = desc.get("Reservations", [])
    if not reservations:
        return None
    return reservations[0]["Instances"][0]["State"]["Name"]


def _get_invocation(ssm, command_id, instance_id):
    try:
        return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except Exception:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
