"""deploy-ec2-3-instance-type-update-reboots-in-place-tags-do-not-drift-tracks-out-of-band-ingress."""

from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-3-instance-type-update-reboots-in-place-tags-do-not-drift-tracks-out-of-band-ingress"
GROUP = "deploy-cfn-ec2-update"
SERVICES = ["cloudformation", "ec2", "ssm"]

_FROM_TYPE = "t3.micro"
_TO_TYPE = "t3.small"
_OOB_PORT = 9443
_OOB_CIDR = "10.99.0.0/16"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An InstanceType update stops/starts the SAME instance (the guest boot id changes), a tags-only
    update does not reboot it, and an out-of-band ingress rule is MODIFIED drift at
    `/SecurityGroupIngress` until revoked, after which the stack is IN_SYNC again."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    az = _usable_az(ec2, [_FROM_TYPE, _TO_TYPE])
    stack_name = ctx.unique_name("sim2real-xsvc-dec3-type-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template()),
        Parameters=[
            {"ParameterKey": "AzName", "ParameterValue": az},
            {"ParameterKey": "InstanceType", "ParameterValue": _FROM_TYPE},
            {"ParameterKey": "MarkerTag", "ParameterValue": "v1"},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": "deploy-ec2-3"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    status = _wait_stack(cfn, stack_id, "CREATE", timeout_s=900)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    outputs = _outputs(cfn, stack_id)
    instance_id = outputs["InstanceId"]
    group_id = outputs["GroupId"]
    assert _physical_id(cfn, stack_id, "Instance") == instance_id, (
        f"stack resource Instance is {_physical_id(cfn, stack_id, 'Instance')!r}, "
        f"output says {instance_id!r}"
    )
    inst = _describe_instance(ec2, instance_id)
    assert inst["InstanceType"] == _FROM_TYPE, (
        f"created instance type is {inst['InstanceType']!r}, expected {_FROM_TYPE!r}"
    )

    _wait_ssm_online(ssm, instance_id, timeout_s=720)
    boot0 = _read_boot(ssm, instance_id)

    # ---- Leg 1: InstanceType change -> same instance, stop/start, new boot ----------------------
    cfn.update_stack(
        StackName=stack_id,
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "AzName", "UsePreviousValue": True},
            {"ParameterKey": "InstanceType", "ParameterValue": _TO_TYPE},
            {"ParameterKey": "MarkerTag", "UsePreviousValue": True},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _wait_stack(cfn, stack_id, "UPDATE", timeout_s=900)
    assert status == "UPDATE_COMPLETE", (
        f"instance-type update ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    after_type = _outputs(cfn, stack_id)["InstanceId"]
    assert after_type == instance_id, (
        f"an InstanceType change must update in place, but the instance id moved "
        f"{instance_id!r} -> {after_type!r}"
    )
    assert _physical_id(cfn, stack_id, "Instance") == instance_id, (
        f"stack resource Instance now {_physical_id(cfn, stack_id, 'Instance')!r}, "
        f"expected the original {instance_id!r}"
    )
    inst = _describe_instance(ec2, instance_id)
    assert inst["InstanceType"] == _TO_TYPE, (
        f"DescribeInstances reports {inst['InstanceType']!r} after the update, expected {_TO_TYPE!r}"
    )
    assert inst["State"]["Name"] == "running", (
        f"instance is {inst['State']['Name']!r} after UPDATE_COMPLETE, expected 'running'"
    )
    boot1 = _read_boot(ssm, instance_id)
    assert boot1["boot_id"] != boot0["boot_id"], (
        f"guest boot_id unchanged ({boot0['boot_id']!r}) across an InstanceType change, "
        "which CloudFormation can only apply by stopping and starting the instance"
    )
    assert boot1["boot_time"] > boot0["boot_time"], (
        f"guest boot time did not advance across the type change: "
        f"{boot0['boot_time']!r} -> {boot1['boot_time']!r}"
    )

    # ---- Leg 2: tags-only change -> no interruption, same boot ----------------------------------
    cfn.update_stack(
        StackName=stack_id,
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "AzName", "UsePreviousValue": True},
            {"ParameterKey": "InstanceType", "UsePreviousValue": True},
            {"ParameterKey": "MarkerTag", "ParameterValue": "v2"},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _wait_stack(cfn, stack_id, "UPDATE", timeout_s=600)
    assert status == "UPDATE_COMPLETE", (
        f"tags-only update ended {status!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    after_tags = _outputs(cfn, stack_id)["InstanceId"]
    assert after_tags == instance_id, (
        f"a tags-only update replaced the instance: {instance_id!r} -> {after_tags!r}"
    )
    inst = _describe_instance(ec2, instance_id)
    marker = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}.get("sim2real:marker")
    assert marker == "v2", f"instance marker tag is {marker!r} after the update, expected 'v2'"
    assert inst["InstanceType"] == _TO_TYPE, (
        f"tags-only update changed the type to {inst['InstanceType']!r}"
    )
    live = _stack_instances(ec2, stack_id)
    assert live == [instance_id], (
        f"non-terminated instances carrying this stack's id are {live!r}; "
        f"expected exactly the original {instance_id!r}"
    )
    boot2 = _read_boot(ssm, instance_id)
    assert boot2["boot_id"] == boot1["boot_id"], (
        f"guest rebooted on a tags-only update: boot_id {boot1['boot_id']!r} -> "
        f"{boot2['boot_id']!r}"
    )
    # `uptime -s` is now - uptime, so a clock slew can move it by a second; the boot_id above is
    # the exact invariant and this bounds the reported boot time to the same boot.
    drift_s = abs((boot2["boot_time"] - boot1["boot_time"]).total_seconds())
    assert drift_s <= 5, (
        f"guest boot time moved {drift_s}s on a tags-only update: "
        f"{boot1['boot_time']!r} -> {boot2['boot_time']!r}"
    )

    # ---- Leg 4: out-of-band ingress -> MODIFIED at /SecurityGroupIngress, revoke -> IN_SYNC ------
    oob = {
        "IpProtocol": "tcp",
        "FromPort": _OOB_PORT,
        "ToPort": _OOB_PORT,
        "IpRanges": [{"CidrIp": _OOB_CIDR, "Description": "sim2real out-of-band"}],
    }
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[oob])
    ctx.on_cleanup(lambda: _revoke_quietly(ec2, group_id, oob))

    drift = _detect_drift(cfn, stack_id)
    assert drift == "DRIFTED", f"stack drift after the out-of-band rule is {drift!r}, expected DRIFTED"
    sg_drift = _resource_drift(cfn, stack_id, "InstanceSg")
    assert sg_drift["StackResourceDriftStatus"] == "MODIFIED", (
        f"security group drift is {sg_drift['StackResourceDriftStatus']!r}, expected MODIFIED"
    )
    paths = [d["PropertyPath"] for d in sg_drift.get("PropertyDifferences", [])]
    assert paths and all(p.startswith("/SecurityGroupIngress") for p in paths), (
        f"drift differences are at {paths!r}; expected them all under /SecurityGroupIngress"
    )
    added = [
        d for d in sg_drift["PropertyDifferences"]
        if d["DifferenceType"] == "ADD" and str(_OOB_PORT) in d.get("ActualValue", "")
    ]
    assert added, (
        f"no ADD difference carrying port {_OOB_PORT}: {sg_drift['PropertyDifferences']!r}"
    )
    inst_drift = _resource_drift(cfn, stack_id, "Instance")
    assert inst_drift["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the instance (changed only through CloudFormation) reports "
        f"{inst_drift['StackResourceDriftStatus']!r} drift: {inst_drift.get('PropertyDifferences')!r}"
    )

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[oob])
    drift = _detect_drift(cfn, stack_id)
    assert drift == "IN_SYNC", f"stack drift after revoking the rule is {drift!r}, expected IN_SYNC"
    sg_drift = _resource_drift(cfn, stack_id, "InstanceSg")
    assert sg_drift["StackResourceDriftStatus"] == "IN_SYNC", (
        f"security group still {sg_drift['StackResourceDriftStatus']!r} after the revoke: "
        f"{sg_drift.get('PropertyDifferences')!r}"
    )

    # ---- Teardown is part of the lifecycle: the stack must reach DELETE_COMPLETE ----------------
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(cfn, stack_id, "DELETE", timeout_s=900)
    assert final == "DELETE_COMPLETE", (
        f"stack delete ended {final!r}: {_failure_reasons(cfn, stack_id)!r}"
    )
    gone = _describe_instance(ec2, instance_id)["State"]["Name"]
    assert gone == "terminated", f"instance {instance_id!r} is {gone!r} after DELETE_COMPLETE"


# ===== helpers =====
_TERMINAL_SUFFIXES = ("_COMPLETE", "_FAILED")


def _template() -> dict:
    tag = [{"Key": "sim2real", "Value": "deploy-ec2-3"}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
            },
            "AzName": {"Type": "String"},
            "InstanceType": {"Type": "String"},
            "MarkerTag": {"Type": "String"},
        },
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.42.0.0/16",
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
                    "CidrBlock": "10.42.1.0/24",
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
            "InstanceSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real deploy-ec2-3 instance group",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [{
                        "IpProtocol": "tcp",
                        "FromPort": 9000,
                        "ToPort": 9000,
                        "CidrIp": "10.42.0.0/16",
                    }],
                    "Tags": tag,
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["DefaultRoute", "SubnetAssoc"],
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": {"Ref": "InstanceType"},
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Fn::GetAtt": ["InstanceSg", "GroupId"]}],
                    "IamInstanceProfile": {"Ref": "SsmProfile"},
                    "Tags": tag + [{"Key": "sim2real:marker", "Value": {"Ref": "MarkerTag"}}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "GroupId": {"Value": {"Fn::GetAtt": ["InstanceSg", "GroupId"]}},
        },
    }


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


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


def _physical_id(cfn, stack_id: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _describe_instance(ec2, instance_id: str) -> dict:
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _stack_instances(ec2, stack_id: str) -> list[str]:
    ids = []
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[
            {"Name": "tag:aws:cloudformation:stack-id", "Values": [stack_id]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "stopping", "stopped"]},
        ]
    ):
        for res in page["Reservations"]:
            ids.extend(i["InstanceId"] for i in res["Instances"])
    return sorted(ids)


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


def _run_shell(ssm, instance_id: str, commands: list[str], *, timeout_s: float = 600) -> str:
    """Run a shell script on the guest; retry until the agent accepts and completes it."""
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
        time.sleep(5)
    raise AssertionError(f"command on {instance_id} never succeeded within {timeout_s}s: {last!r}")


def _read_boot(ssm, instance_id: str) -> dict:
    out = _run_shell(
        ssm, instance_id,
        ["echo BOOTID=$(cat /proc/sys/kernel/random/boot_id)", "echo BOOTTIME=$(uptime -s)"],
    )
    fields = dict(
        line.split("=", 1) for line in out.splitlines() if line.startswith(("BOOTID=", "BOOTTIME="))
    )
    assert set(fields) == {"BOOTID", "BOOTTIME"}, f"unparseable boot read: {out!r}"
    return {
        "boot_id": fields["BOOTID"].strip(),
        "boot_time": datetime.strptime(fields["BOOTTIME"].strip(), "%Y-%m-%d %H:%M:%S"),
    }


def _detect_drift(cfn, stack_id: str, *, timeout_s: float = 300) -> str:
    did = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]
    deadline = time.monotonic() + timeout_s
    st = None
    while time.monotonic() < deadline:
        st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=did)
        if st["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            assert st["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection ended {st['DetectionStatus']!r}: {st.get('DetectionStatusReason')!r}"
            )
            return st["StackDriftStatus"]
        time.sleep(5)
    raise AssertionError(f"drift detection still running after {timeout_s}s: {st!r}")


def _resource_drift(cfn, stack_id: str, logical: str) -> dict:
    token = None
    while True:
        kw = {"StackName": stack_id}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        for d in page["StackResourceDrifts"]:
            if d["LogicalResourceId"] == logical:
                return d
        token = page.get("NextToken")
        if not token:
            raise AssertionError(f"no drift record for {logical!r} in stack {stack_id!r}")


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
