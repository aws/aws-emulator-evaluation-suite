"""deploy-ec2-instance-from-launch-template-inherits-its-properties."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-from-launch-template-inherits-its-properties"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.83.0.0/16"
SUBNET_BLOCK = "10.83.0.0/24"

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


def _template(instance_type: str) -> dict[str, Any]:
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
            "Lt": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {
                        "ImageId": {"Ref": "Ami"},
                        "InstanceType": instance_type,
                    },
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "SubnetId": {"Ref": "Subnet"},
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "Lt"},
                        "Version": {"Fn::GetAtt": ["Lt", "LatestVersionNumber"]},
                    },
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Fn::GetAtt": ["Instance", "InstanceId"]}},
            "LaunchTemplateId": {"Value": {"Ref": "Lt"}},
        },
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


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN EC2 instance that names a launch template with no property overrides launches with
    that template's ImageId and InstanceType, the template holds exactly that one version, and
    deleting the stack terminates the instance and removes the template.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    instance_type, az = _cheapest_in_an_az(ec2)

    name = ctx.unique_name("sim2real-xsvc-ltinst-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template(instance_type)),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

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
    lt_id = outputs["LaunchTemplateId"]

    resolved_ami = next(
        p["ResolvedValue"] for p in stack["Parameters"] if p["ParameterKey"] == "Ami"
    )

    def instance():
        return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]

    inst = _poll(
        ctx,
        f"instance {instance_id} running",
        instance,
        lambda i: i["State"]["Name"] == "running",
        300.0,
    )
    assert inst["InstanceType"] == instance_type, (
        f"EC2 reports instance type {inst['InstanceType']!r}, but the launch template declares "
        f"{instance_type!r} and the instance overrides nothing"
    )
    assert inst["ImageId"] == resolved_ami, (
        f"EC2 reports ImageId {inst['ImageId']!r}, but the launch template resolved "
        f"{AMI_PARAMETER!r} to {resolved_ami!r}"
    )

    versions = [
        (v["VersionNumber"], v["LaunchTemplateData"])
        for v in ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)[
            "LaunchTemplateVersions"
        ]
    ]
    want_versions = [(1, {"ImageId": resolved_ami, "InstanceType": instance_type})]
    assert versions == want_versions, (
        f"the launch template's versions read {versions!r}, expected exactly {want_versions!r}"
    )

    _delete_stack_and_wait(cfn, stack_id)
    _poll(
        ctx,
        f"instance {instance_id} terminated",
        instance,
        lambda i: i["State"]["Name"] == "terminated",
        300.0,
    )
    got = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id]))
    want = (
        "InvalidLaunchTemplateId.NotFound",
        "At least one of the launch templates specified in the request does not exist.",
    )
    assert got == want, f"expected {want!r} once the stack is deleted, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
