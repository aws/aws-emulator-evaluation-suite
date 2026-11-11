"""deploy-ec2-network-interface-and-volume-attachment-read-back-and-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-network-interface-and-volume-attachment-read-back-and-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.83.0.0/16"
SUBNET_BLOCK = "10.83.0.0/24"
VOLUME_SIZE_GIB = 1
DEVICE = "/dev/sdf"


def _template(with_attachments: bool = True) -> dict[str, Any]:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
            "Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                     "Default": AMI_PARAMETER},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": SUBNET_BLOCK,
                "AvailabilityZone": {"Ref": "Az"}}},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real-xsvc-nicvol", "VpcId": {"Ref": "Vpc"}}},
            "Instance": {"Type": "AWS::EC2::Instance", "Properties": {
                "ImageId": {"Ref": "Ami"}, "InstanceType": INSTANCE_TYPE,
                "SubnetId": {"Ref": "Subnet"}, "SecurityGroupIds": [{"Ref": "Sg"}],
            }},
            "Eni": {"Type": "AWS::EC2::NetworkInterface", "Properties": {
                "SubnetId": {"Ref": "Subnet"}, "GroupSet": [{"Ref": "Sg"}],
            }},
            "NicAttach": {"Type": "AWS::EC2::NetworkInterfaceAttachment", "Properties": {
                "InstanceId": {"Ref": "Instance"}, "NetworkInterfaceId": {"Ref": "Eni"},
                "DeviceIndex": 1,
            }},
            "Volume": {"Type": "AWS::EC2::Volume", "Properties": {
                "AvailabilityZone": {"Ref": "Az"}, "Size": VOLUME_SIZE_GIB,
            }},
            "VolAttach": {"Type": "AWS::EC2::VolumeAttachment", "Properties": {
                "InstanceId": {"Ref": "Instance"}, "VolumeId": {"Ref": "Volume"}, "Device": DEVICE,
            }},
        },
        "Outputs": {
            "InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "InstanceId"]}},
            "EniId": {"Value": {"Ref": "Eni"}},
            "AttachmentId": {"Value": {"Ref": "NicAttach"}},
            "VolumeId": {"Value": {"Ref": "Volume"}},
            "EniPrivateIp": {"Value": {"Fn::GetAtt": ["Eni", "PrimaryPrivateIpAddress"]}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
        },
    }
    if not with_attachments:
        for logical_id in ("NicAttach", "VolAttach"):
            del template["Resources"][logical_id]
        del template["Outputs"]["AttachmentId"]
    return template


def _eni_not_found(eni_id: str) -> tuple[str, str]:
    return ("InvalidNetworkInterfaceID.NotFound", f"The networkInterface ID '{eni_id}' does not exist")


def _volume_not_found(volume_id: str) -> tuple[str, str]:
    return ("InvalidVolume.NotFound", f"The volume '{volume_id}' does not exist.")


def _settle(read, done, timeout_s: float = 120.0):
    """Poll ``read()`` every 2 s until ``done(value)`` or the deadline; return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = read()
        if done(value) or time.monotonic() > deadline:
            return value
        time.sleep(2)


def _usable_az(ec2) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN network-interface attachment and volume attachment read back through EC2's own
    DescribeNetworkInterfaces and DescribeVolumes, and deleting the stack detaches both and
    removes the interface and the volume, which EC2 answers with its own not-found signal.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)

    stack_name = ctx.unique_name("sim2real-xsvc-nicvol-")
    stack_id = create_stack(
        ctx, cfn, stack_name, json.dumps(_template()),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
    )
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    subnet_id, sg_id = outputs["SubnetId"], outputs["SgId"]
    params = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Parameters"]
    ami = next(p["ResolvedValue"] for p in params if p["ParameterKey"] == "Ami")

    instance_id = outputs["InstanceId"]
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    got = (inst["InstanceType"], inst["ImageId"], inst["SubnetId"],
           [g["GroupId"] for g in inst["SecurityGroups"]])
    assert got == (INSTANCE_TYPE, ami, subnet_id, [sg_id]), f"instance reads {got!r}"
    eni_id = outputs["EniId"]
    volume_id = outputs["VolumeId"]

    enis = paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                    Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]},
                             {"Name": "attachment.device-index", "Values": ["1"]}])
    assert [e["NetworkInterfaceId"] for e in enis] == [eni_id], (
        f"interfaces at device index 1 of {instance_id!r}: {enis!r}, Ref {eni_id!r}"
    )
    eni = enis[0]
    got = (eni["SubnetId"], [g["GroupId"] for g in eni["Groups"]], eni["PrivateIpAddress"])
    assert got == (subnet_id, [sg_id], outputs["EniPrivateIp"]), f"interface reads {got!r}"
    attachment = eni["Attachment"]
    assert attachment["AttachmentId"] == outputs["AttachmentId"], (
        f"EC2's Attachment.AttachmentId {attachment['AttachmentId']!r} disagrees with the "
        f"stack's Ref value {outputs['AttachmentId']!r}"
    )
    assert attachment["InstanceId"] == instance_id, (
        f"EC2 reports the interface attached to {attachment['InstanceId']!r}, expected {instance_id!r}"
    )
    assert attachment["DeviceIndex"] == 1, f"EC2 reports device index {attachment['DeviceIndex']!r}, expected 1"

    vols = paginate(ec2, "describe_volumes", "Volumes",
                    Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]},
                             {"Name": "attachment.device", "Values": [DEVICE]}])
    assert [v["VolumeId"] for v in vols] == [volume_id], (
        f"volumes at {DEVICE} of {instance_id!r}: {vols!r}, Ref {volume_id!r}"
    )
    volume = vols[0]
    assert (volume["Size"], volume["AvailabilityZone"]) == (VOLUME_SIZE_GIB, az), (
        f"volume (Size, AvailabilityZone) {(volume['Size'], volume['AvailabilityZone'])!r}"
    )
    vol_attachments = volume["Attachments"]
    assert len(vol_attachments) == 1, f"EC2 reports {len(vol_attachments)} volume attachments, expected 1"
    vol_attach = vol_attachments[0]
    assert vol_attach["InstanceId"] == instance_id, (
        f"EC2 reports the volume attached to {vol_attach['InstanceId']!r}, expected {instance_id!r}"
    )
    assert vol_attach["Device"] == DEVICE, f"EC2 reports device {vol_attach['Device']!r}, expected {DEVICE!r}"
    assert vol_attach["State"] == "attached", f"EC2 reports volume attachment state {vol_attach['State']!r}"

    # Each attachment's own delete: an update dropping both detaches them from the live instance.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=json.dumps(_template(with_attachments=False)),
        Parameters=[{"ParameterKey": "Az", "UsePreviousValue": True},
                    {"ParameterKey": "Ami", "UsePreviousValue": True}],
    )
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"attachment-removing update ended {status!r}"
    # Detach is asynchronous: poll each read to its detached state within a bound.
    def eni_read():
        e = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
        return e["Status"], e.get("Attachment")

    def volume_read():
        v = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
        return v["State"], v["Attachments"]

    eni_state = _settle(eni_read, lambda v: v == ("available", None))
    assert eni_state == ("available", None), (
        f"after dropping NicAttach the interface reads {eni_state!r}"
    )
    volume_state = _settle(volume_read, lambda v: v == ("available", []))
    assert volume_state == ("available", []), (
        f"after dropping VolAttach the volume reads {volume_state!r}"
    )

    delete_stack(cfn, stack_id)
    eni_gone = _eni_not_found(eni_id)
    volume_gone = _volume_not_found(volume_id)
    expect_error(lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]), *eni_gone)
    expect_error(lambda: ec2.describe_volumes(VolumeIds=[volume_id]), *volume_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
