"""deploy-ec2-instance-block-device-mapping-read-back-through-describe-volumes."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-block-device-mapping-read-back-through-describe-volumes"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.84.0.0/16"
SUBNET_BLOCK = "10.84.0.0/24"
DEVICE_NAME = "/dev/sdb"
VOLUME_SIZE = 8
VOLUME_TYPE = "gp3"
RUN_TAG_KEY = "sim2real-run"

_CHEAP_CANDIDATES = ("t3.nano", "t3.micro", "t2.nano", "t2.micro")


def _cheapest_in_an_az(ec2) -> tuple[str, str]:
    """``(instance type, AZ)``: the cheapest of ``_CHEAP_CANDIDATES`` DescribeInstanceTypeOfferings
    reports for some available AZ."""
    usable_azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    for az in usable_azs:
        offered = {
            o["InstanceType"]
            for o in ec2.describe_instance_type_offerings(
                LocationType="availability-zone", Filters=[{"Name": "location", "Values": [az]}]
            )["InstanceTypeOfferings"]
        }
        for candidate in _CHEAP_CANDIDATES:
            if candidate in offered:
                return candidate, az
    raise AssertionError(
        f"none of {_CHEAP_CANDIDATES!r} is offered in any available AZ of {usable_azs!r}"
    )


def _template(instance_type: str, run_tag: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
            "Ami": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": AMI_PARAMETER,
            },
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": SUBNET_BLOCK,
                    "AvailabilityZone": {"Ref": "Az"},
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "Ami"},
                    "InstanceType": instance_type,
                    "SubnetId": {"Ref": "Subnet"},
                    "PropagateTagsToVolumeOnCreation": True,
                    "Tags": [{"Key": RUN_TAG_KEY, "Value": run_tag}],
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": DEVICE_NAME,
                            "Ebs": {
                                "VolumeSize": VOLUME_SIZE,
                                "VolumeType": VOLUME_TYPE,
                                "DeleteOnTermination": False,
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "InstanceId"]}}},
    }


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, what: str, read, done, cap_s: float, interval_s: float = 3.0):
    """``read()`` polled until ``done(value)``, against a deadline capped by the run budget."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    last = read()
    while not done(last):
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} did not happen within {cap_s:.0f}s (last={last!r})")
        time.sleep(interval_s)
        last = read()
    return last


def _stack(cfn, stack_id: str) -> dict[str, Any]:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, timeout_s: float = 900.0) -> None:
    """Delete the stack by id, whatever its state, and wait for DELETE_COMPLETE; anything else
    raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    final = _stack(cfn, stack_id)
    while final["StackStatus"] not in ("DELETE_COMPLETE", "DELETE_FAILED"):
        if time.monotonic() > deadline:
            break
        time.sleep(5)
        final = _stack(cfn, stack_id)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _volume_not_found(volume_id: str) -> tuple[str, str]:
    return "InvalidVolume.NotFound", f"The volume '{volume_id}' does not exist."


def _delete_run_volumes(ec2, run_tag: str, timeout_s: float = 600.0) -> None:
    """Delete every volume carrying this run's tag once it is detached; a volume EC2 is already
    deleting is left to finish, and only the exact not-found means one is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        volumes = [
            v
            for page in ec2.get_paginator("describe_volumes").paginate(
                Filters=[{"Name": f"tag:{RUN_TAG_KEY}", "Values": [run_tag]}]
            )
            for v in page["Volumes"]
        ]
        pending = [v for v in volumes if v["State"] not in ("deleting", "deleted")]
        if not pending:
            return
        for vol in pending:
            if vol["State"] != "available":
                continue
            try:
                ec2.delete_volume(VolumeId=vol["VolumeId"])
            except ClientError as exc:
                err = exc.response["Error"]
                if (err.get("Code"), err.get("Message")) != _volume_not_found(vol["VolumeId"]):
                    raise
        if time.monotonic() > deadline:
            raise RuntimeError(
                f"volumes of run {run_tag} still present: "
                f"{[(v['VolumeId'], v['State']) for v in pending]!r}"
            )
        time.sleep(5)


def _teardown(cfn, ec2, stack_id: str, run_tag: str):
    """Delete the stack, then every volume its instance left behind; the volume pass runs even
    when the stack delete fails, and any failure raises."""

    def run_teardown() -> None:
        try:
            _delete_stack_and_wait(cfn, stack_id)
        except BaseException as stack_exc:
            # The volume pass must not replace the stack delete's own failure.
            try:
                _delete_run_volumes(ec2, run_tag)
            except Exception as volume_exc:
                stack_exc.add_note(f"volume cleanup also failed: {volume_exc!r}")
            raise
        _delete_run_volumes(ec2, run_tag)

    return run_teardown


def _describe_volume_or_error(ec2, volume_id: str):
    """The volume, or the (code, message) DescribeVolumes refuses it with."""
    try:
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN EC2 instance's non-root BlockDeviceMapping (size, type, DeleteOnTermination) is the
    one volume DescribeVolumes reports attached to it; with DeleteOnTermination false the volume
    outlives the instance's termination as an available, unattached volume.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    instance_type, az = _cheapest_in_an_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-ec2bdm-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template(instance_type, name)),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(_teardown(cfn, ec2, stack_id, name))

    stack = _poll(
        ctx,
        f"stack {stack_id} reaching a terminal create status",
        lambda: _stack(cfn, stack_id),
        lambda st: not st["StackStatus"].endswith("_IN_PROGRESS"),
        900.0,
        5.0,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    instance_id = outputs["InstanceId"]

    def instance():
        return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]

    inst = _poll(
        ctx,
        f"instance {instance_id} running",
        instance,
        lambda i: i["State"]["Name"] == "running",
        300.0,
    )
    mappings = [m for m in inst["BlockDeviceMappings"] if m["DeviceName"] == DEVICE_NAME]
    assert len(mappings) == 1, (
        f"expected exactly one BlockDeviceMapping for {DEVICE_NAME!r}, got "
        f"{[m['DeviceName'] for m in inst['BlockDeviceMappings']]!r}"
    )
    volume_id = mappings[0]["Ebs"]["VolumeId"]

    vol = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert vol["Size"] == VOLUME_SIZE, (
        f"DescribeVolumes reports size {vol['Size']!r}, expected the template's {VOLUME_SIZE!r}"
    )
    assert vol["VolumeType"] == VOLUME_TYPE, (
        f"DescribeVolumes reports type {vol['VolumeType']!r}, expected the template's "
        f"{VOLUME_TYPE!r}"
    )
    attachments = [
        (a["VolumeId"], a["InstanceId"], a["Device"], a["DeleteOnTermination"])
        for a in vol["Attachments"]
    ]
    want_attachments = [(volume_id, instance_id, DEVICE_NAME, False)]
    assert attachments == want_attachments, (
        f"DescribeVolumes' attachments are {attachments!r}, expected exactly {want_attachments!r}"
    )

    _delete_stack_and_wait(cfn, stack_id)
    _poll(
        ctx,
        f"instance {instance_id} terminated",
        instance,
        lambda i: i["State"]["Name"] == "terminated",
        300.0,
    )
    # The root EBS volume's own DeleteOnTermination defaults true, so it is deleted; this volume's
    # DeleteOnTermination is false and DescribeVolumes still reports it, now detached.
    survived = _poll(
        ctx,
        f"volume {volume_id} detaching",
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        180.0,
    )
    assert survived["Attachments"] == [], (
        f"the available volume still lists attachments {survived['Attachments']!r}"
    )

    ec2.delete_volume(VolumeId=volume_id)
    # A just-deleted volume answers its own 'deleting' state until the deletion completes.
    gone = _poll(
        ctx,
        f"volume {volume_id} deleted",
        lambda: _describe_volume_or_error(ec2, volume_id),
        lambda r: isinstance(r, tuple),
        120.0,
    )
    assert gone == _volume_not_found(volume_id), (
        f"expected {_volume_not_found(volume_id)!r} once the volume is deleted, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
