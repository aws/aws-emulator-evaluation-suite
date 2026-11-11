"""deploy-ec2-3-group-rename-replaces-the-group-and-source-group-rule-still-drops-an-unrelated-instance."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-3-group-rename-replaces-the-group-and-source-group-rule-still-drops-an-unrelated-instance"
GROUP = "deploy-cfn-ec2-update"
SERVICES = ["cloudformation", "ec2", "ssm"]

_PORT = 8080
_TYPE = "t3.micro"

# Runs INSIDE the source / unrelated guest via SSM. A security group that does not admit a flow
# DROPS it, so a refused peer is a connect TIMEOUT, never a reset.
_PROBE = r'''
import socket, sys
ip = sys.argv[1]
try:
    s = socket.create_connection((ip, %d), timeout=5)
    s.sendall(b"GET /token HTTP/1.0\r\nHost: probe\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print("RESULT=OPEN " + data.split(b"\r\n\r\n", 1)[-1].decode().strip())
except (socket.timeout, TimeoutError):
    print("RESULT=TIMEOUT")
except Exception as exc:
    print("RESULT=ERR " + type(exc).__name__)
''' % _PORT


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """Renaming a stack's SecurityGroup (a replacement property) mints a new group, moves the same
    instance onto it and deletes the old one; its SourceSecurityGroupId rule still admits TCP from
    the source guest while dropping an unrelated guest until that guest's group is authorized.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    az = _usable_az(ec2, [_TYPE])
    old_name = ctx.unique_name("sim2real-xsvc-dec3-tgt-a-")
    new_name = ctx.unique_name("sim2real-xsvc-dec3-tgt-b-")
    stack_name = ctx.unique_name("sim2real-xsvc-dec3-sg-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template()),
        Parameters=[
            {"ParameterKey": "AzName", "ParameterValue": az},
            {"ParameterKey": "TargetGroupName", "ParameterValue": old_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": "deploy-ec2-3"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _wait_stack(cfn, stack_id, "CREATE", timeout_s=_bounded(ctx, 900))
    assert status == "CREATE_COMPLETE", (
        f"stack create ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    out = _outputs(cfn, stack_id)
    target_id, source_id, other_id = out["TargetId"], out["SourceId"], out["OtherId"]
    old_gid, source_gid, other_gid = out["TargetGroupId"], out["SourceGroupId"], out["OtherGroupId"]
    target_ip = _describe_instance(ec2, target_id)["PrivateIpAddress"]

    for iid in (target_id, source_id, other_id):
        _wait_ssm_online(ssm, iid, timeout_s=_bounded(ctx, 720))

    token = uuid.uuid4().hex
    _run_shell(ctx, ssm, target_id, [
        "mkdir -p /srv/s2r",
        f"echo {token} > /srv/s2r/token",
        f"systemd-run --unit=s2r-listener-{token[:8]} python3 -m http.server {_PORT} "
        "--bind 0.0.0.0 --directory /srv/s2r",
    ])
    local = _poll_probe(ctx, ssm, target_id, "127.0.0.1", want=f"OPEN {token}", timeout_s=60)
    assert local == f"OPEN {token}", f"target's own listener did not serve the token: {local!r}"

    # Baseline before the rename: the source group is admitted, the unrelated group is dropped.
    got = _poll_probe(ctx, ssm, source_id, target_ip, want=f"OPEN {token}", timeout_s=120)
    assert got == f"OPEN {token}", f"source guest could not fetch from the target before rename: {got!r}"
    got = _probe(ctx, ssm, other_id, target_ip)
    assert got == "TIMEOUT", f"unrelated guest reached the target before rename: {got!r}"

    # ---- Leg 3: GroupName change -> replacement group, same instance ----------------------------
    cfn.update_stack(
        StackName=stack_id,
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "AzName", "UsePreviousValue": True},
            {"ParameterKey": "TargetGroupName", "ParameterValue": new_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _wait_stack(cfn, stack_id, "UPDATE", timeout_s=_bounded(ctx, 900))
    assert status == "UPDATE_COMPLETE", (
        f"group rename update ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    out = _outputs(cfn, stack_id)
    new_gid = out["TargetGroupId"]
    assert new_gid != old_gid, f"GroupName change kept the same GroupId {old_gid!r}"
    assert out["TargetId"] == target_id, (
        f"group rename replaced the instance: {target_id!r} -> {out['TargetId']!r}"
    )

    new_sg = ec2.describe_security_groups(GroupIds=[new_gid])["SecurityGroups"][0]
    assert new_sg["GroupName"] == new_name, (
        f"replacement group is named {new_sg['GroupName']!r}, expected {new_name!r}"
    )
    pairs = [
        (p.get("FromPort"), g["GroupId"])
        for p in new_sg["IpPermissions"] for g in p.get("UserIdGroupPairs", [])
    ]
    assert pairs == [(_PORT, source_gid)], (
        f"replacement group's SG-to-SG ingress is {pairs!r}, expected [({_PORT}, {source_gid!r})]"
    )

    old_code, message = _poll_error(lambda: ec2.describe_security_groups(GroupIds=[old_gid]),
                                    timeout_s=_bounded(ctx, 120))
    assert old_code == "InvalidGroup.NotFound", (
        f"describing the replaced group {old_gid!r} returned {old_code!r}, "
        "expected InvalidGroup.NotFound"
    )
    assert message == f"The security group '{old_gid}' does not exist", (
        f"DescribeSecurityGroups InvalidGroup.NotFound message: {message!r}"
    )

    inst = _describe_instance(ec2, target_id)
    attached = sorted(g["GroupId"] for g in inst["SecurityGroups"])
    assert attached == [new_gid], (
        f"instance {target_id!r} is in groups {attached!r}, expected only the replacement {new_gid!r}"
    )
    assert inst["State"]["Name"] == "running", f"target is {inst['State']['Name']!r} after rename"

    # Differential: each refused attempt by the unrelated guest sits between two successful
    # fetches by the source guest against the same listener through the same group.
    got = _poll_probe(ctx, ssm, source_id, target_ip, want=f"OPEN {token}", timeout_s=120)
    assert got == f"OPEN {token}", f"source guest lost access after the rename: {got!r}"
    for attempt in range(3):
        got = _probe(ctx, ssm, other_id, target_ip)
        assert got == "TIMEOUT", (
            f"unrelated guest reached the target through the replacement group "
            f"(attempt {attempt + 1}): {got!r}"
        )
        got = _poll_probe(ctx, ssm, source_id, target_ip, want=f"OPEN {token}", timeout_s=60)
        assert got == f"OPEN {token}", (
            f"source guest refused between unrelated attempts (attempt {attempt + 1}): {got!r}"
        )

    # Close the loop: admit the unrelated guest's group and the same probe must now succeed, so
    # the drops above were the group's decision and not a broken guest.
    repair = {
        "IpProtocol": "tcp",
        "FromPort": _PORT,
        "ToPort": _PORT,
        "UserIdGroupPairs": [{"GroupId": other_gid, "Description": "sim2real repair"}],
    }
    ec2.authorize_security_group_ingress(GroupId=new_gid, IpPermissions=[repair])
    ctx.on_cleanup(lambda: _revoke_quietly(ec2, new_gid, repair))
    got = _poll_probe(ctx, ssm, other_id, target_ip, want=f"OPEN {token}", timeout_s=120)
    assert got == f"OPEN {token}", (
        f"unrelated guest still refused after its group was admitted: {got!r}"
    )
    ec2.revoke_security_group_ingress(GroupId=new_gid, IpPermissions=[repair])

    # ---- Teardown is part of the lifecycle: the stack must reach DELETE_COMPLETE ----------------
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(cfn, stack_id, "DELETE", timeout_s=_bounded(ctx, 900))
    assert final == "DELETE_COMPLETE", (
        f"stack delete ended {final!r}: {_failure_reasons(cfn, stack_id)!r}"
    )


_TERMINAL_SUFFIXES = ("_COMPLETE", "_FAILED")


def _template() -> dict:
    tag = [{"Key": "sim2real", "Value": "deploy-ec2-3"}]

    def instance(group: str) -> dict:
        return {
            "Type": "AWS::EC2::Instance",
            "DependsOn": ["DefaultRoute", "SubnetAssoc"],
            "Properties": {
                "ImageId": {"Ref": "AmiId"},
                "InstanceType": _TYPE,
                "SubnetId": {"Ref": "Subnet"},
                "SecurityGroupIds": [{"Fn::GetAtt": [group, "GroupId"]}],
                "IamInstanceProfile": {"Ref": "SsmProfile"},
                "Tags": tag,
            },
        }

    def plain_group(desc: str) -> dict:
        return {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {"GroupDescription": desc, "VpcId": {"Ref": "Vpc"}, "Tags": tag},
        }

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            },
            "AzName": {"Type": "String"},
            "TargetGroupName": {"Type": "String"},
        },
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.43.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": tag,
                },
            },
            "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": tag}},
            "IgwAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.43.1.0/24",
                    "AvailabilityZone": {"Ref": "AzName"},
                    "MapPublicIpOnLaunch": True,
                    "Tags": tag,
                },
            },
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": tag},
            },
            "DefaultRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IgwAttach",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "Igw"},
                },
            },
            "SubnetAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "Subnet"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "SsmRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
                    "Tags": tag,
                },
            },
            "SsmProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "SourceSg": plain_group("sim2real deploy-ec2-3 source group"),
            "OtherSg": plain_group("sim2real deploy-ec2-3 unrelated group"),
            "TargetSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupName": {"Ref": "TargetGroupName"},
                    "GroupDescription": "sim2real deploy-ec2-3 target group",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [{
                        "IpProtocol": "tcp",
                        "FromPort": _PORT,
                        "ToPort": _PORT,
                        "SourceSecurityGroupId": {"Fn::GetAtt": ["SourceSg", "GroupId"]},
                    }],
                    "Tags": tag,
                },
            },
            "Target": instance("TargetSg"),
            "Source": instance("SourceSg"),
            "Other": instance("OtherSg"),
        },
        "Outputs": {
            "TargetId": {"Value": {"Ref": "Target"}},
            "SourceId": {"Value": {"Ref": "Source"}},
            "OtherId": {"Value": {"Ref": "Other"}},
            "TargetGroupId": {"Value": {"Fn::GetAtt": ["TargetSg", "GroupId"]}},
            "SourceGroupId": {"Value": {"Fn::GetAtt": ["SourceSg", "GroupId"]}},
            "OtherGroupId": {"Value": {"Fn::GetAtt": ["OtherSg", "GroupId"]}},
        },
    }


def _bounded(ctx, cap_s: float, reserve_s: float = 10.0) -> float:
    """`cap_s`, shortened so the wait ends `reserve_s` before the runner stops the check."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


class _NoError(Exception):
    """The call that was expected to fail succeeded."""


def _poll_error(fn, *, timeout_s: float) -> tuple[str, str]:
    """Return the error (code, message) once ``fn`` fails; a success that never stops raises _NoError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return _code(exc), exc.response.get("Error", {}).get("Message", "")
        if time.monotonic() >= deadline:
            raise _NoError(f"call kept succeeding for {timeout_s}s: {result!r}")
        time.sleep(2)


def _usable_az(ec2, types: list[str]) -> str:
    offered = None
    for want in types:
        zones = {
            o["Location"]
            for o in ec2.describe_instance_type_offerings(
                LocationType="availability-zone",
                Filters=[{"Name": "instance-type", "Values": [want]}],
            )["InstanceTypeOfferings"]
        }
        offered = zones if offered is None else offered & zones
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers all of {types!r}; offered {sorted(offered)!r}"
    return usable[0]


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _wait_stack(cfn, stack_id: str, op: str, *, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _stack(cfn, stack_id)["StackStatus"]
        if status.endswith(_TERMINAL_SUFFIXES) and "IN_PROGRESS" not in status:
            if status.startswith(op) or "ROLLBACK" in status:
                return status
        time.sleep(2)
    raise AssertionError(f"stack {op} still {status!r} after {timeout_s}s")


def _failure_reasons(cfn, stack_id: str) -> list:
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ][:5]


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}


def _describe_instance(ec2, instance_id: str) -> dict:
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _wait_ssm_online(ssm, instance_id: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        if last and last[0]["PingStatus"] == "Online":
            return
        time.sleep(2)
    raise AssertionError(f"{instance_id} never came Online in SSM within {timeout_s}s: {last!r}")


def _run_shell(ctx, ssm, instance_id: str, commands: list[str], *, timeout_s: float = 600) -> str:
    """Run a shell script on the guest; retry until the agent accepts and completes it."""
    timeout_s = _bounded(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            cid = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands, "executionTimeout": ["120"]},
                TimeoutSeconds=120,
                Comment="sim2real deploy-ec2-3",
            )["Command"]["CommandId"]
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceId":
                raise
            last = f"send_command: {_code(exc)}"
            time.sleep(2)
            continue
        inv_deadline = min(deadline, time.monotonic() + 300)
        while time.monotonic() < inv_deadline:
            time.sleep(3)
            try:
                inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
            except ClientError as exc:
                if _code(exc) == "InvocationDoesNotExist":
                    continue
                raise
            if inv["Status"] == "Success":
                return inv["StandardOutputContent"]
            if inv["Status"] not in {"Pending", "InProgress", "Delayed"}:
                last = (inv["Status"], inv.get("StandardErrorContent", "")[-300:])
                break
        time.sleep(2)
    raise AssertionError(f"command on {instance_id} never succeeded within {timeout_s}s: {last!r}")


def _probe(ctx, ssm, from_id: str, ip: str) -> str:
    """One TCP+HTTP attempt from inside ``from_id`` to ``ip``: 'OPEN <body>', 'TIMEOUT' or 'ERR x'."""
    out = _run_shell(ctx, ssm, from_id, [
        "cat > /tmp/s2r_probe.py <<'S2REOF'",
        *_PROBE.strip("\n").splitlines(),
        "S2REOF",
        f"python3 /tmp/s2r_probe.py {ip}",
    ])
    lines = [ln[len("RESULT="):] for ln in out.splitlines() if ln.startswith("RESULT=")]
    assert len(lines) == 1, f"probe from {from_id} printed no single RESULT line: {out!r}"
    return lines[0].strip()


def _poll_probe(ctx, ssm, from_id: str, ip: str, *, want: str, timeout_s: float) -> str:
    """Repeat a probe until it returns ``want`` (an admit can lag a group change); return the last."""
    deadline = time.monotonic() + _bounded(ctx, timeout_s)
    got = _probe(ctx, ssm, from_id, ip)
    while got != want and time.monotonic() < deadline:
        time.sleep(2)
        got = _probe(ctx, ssm, from_id, ip)
    return got


def _revoke_quietly(ec2, group_id: str, perm: dict) -> None:
    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[perm])
    except ClientError as exc:
        if _code(exc) not in {"InvalidPermission.NotFound", "InvalidGroup.NotFound"}:
            raise RuntimeError(f"out-of-band rule on {group_id}: {exc}") from exc


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    try:
        if _stack(cfn, stack_id)["StackStatus"] == "DELETE_COMPLETE":
            return
        cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            status = _stack(cfn, stack_id)["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(
                    f"stack {stack_id} DELETE_FAILED: {_failure_reasons(cfn, stack_id)}"
                )
            time.sleep(10)
        raise RuntimeError(f"stack {stack_id} not deleted within 900s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} teardown failed: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
