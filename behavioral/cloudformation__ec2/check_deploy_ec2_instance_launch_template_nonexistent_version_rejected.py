"""deploy-ec2-instance-launch-template-nonexistent-version-rejected."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-launch-template-nonexistent-version-rejected"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
VPC_BLOCK = "10.85.0.0/16"
SUBNET_BLOCK = "10.85.0.0/24"
_ABSENT_VERSION = "99"

_CHEAP_CANDIDATES = ("t3.nano", "t3.micro", "t2.nano", "t2.micro")

# AWS::EC2::Instance's resource provider relays EC2's launch-template-version refusal with no
# Error Code field of its own; the request id, SDK attempt count and request token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r"Status Code: (?P<status>\d+), Request ID: [^)]*\) \(SDK Attempt Count: \d+\)\" "
    r"\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler_code>[A-Za-z]+)\)$"
)


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


def _template(lt_id: str, version: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Az": {"Type": "String"}},
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
                    "SubnetId": {"Ref": "Subnet"},
                    "LaunchTemplate": {"LaunchTemplateId": lt_id, "Version": version},
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


def _lt_not_found(lt_id: str) -> tuple[str, str]:
    return (
        "InvalidLaunchTemplateId.NotFound",
        f"The specified launch template, with template ID {lt_id}, does not exist.",
    )


def _delete_launch_template(ec2, lt_id: str) -> None:
    """Delete the launch template; only its exact not-found means it is already gone."""
    try:
        ec2.delete_launch_template(LaunchTemplateId=lt_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) != _lt_not_found(lt_id):
            raise


def _stack_instances(ec2, stack_id: str) -> list[str]:
    """Ids of every instance (any state) tagged with this stack's id."""
    return sorted(
        i["InstanceId"]
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:aws:cloudformation:stack-id", "Values": [stack_id]}]
        )
        for r in page["Reservations"]
        for i in r["Instances"]
    )


def _wait_create(ctx, cfn, stack_id: str) -> dict[str, Any]:
    return _poll(
        ctx,
        f"stack {stack_id} reaching a terminal create status",
        lambda: _stack(cfn, stack_id),
        lambda st: not st["StackStatus"].endswith("_IN_PROGRESS"),
        900.0,
        5.0,
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN EC2 instance whose LaunchTemplate names a version the template does not have is
    rejected by EC2 and the stack launches no instance; the launch template's own existing
    version still launches one.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    instance_type, az = _cheapest_in_an_az(ec2)

    lt_name = ctx.unique_name("sim2real-xsvc-ltverinst-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _al2023_ami(ec2), "InstanceType": instance_type},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _delete_launch_template(ec2, lt_id))
    versions = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)[
        "LaunchTemplateVersions"
    ]
    assert [v["VersionNumber"] for v in versions] == [1], (
        f"a freshly created launch template should carry exactly version 1, got {versions!r}"
    )

    bad_stack_name = ctx.unique_name("sim2real-xsvc-ltverinstbad-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps(_template(lt_id, _ABSENT_VERSION)),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": bad_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    bad_stack = _wait_create(ctx, cfn, bad_stack_id)
    assert bad_stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"an instance naming launch template version {_ABSENT_VERSION!r}, which does not exist, "
        f"ended {bad_stack['StackStatus']!r}, expected 'ROLLBACK_COMPLETE'"
    )
    events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack_id)
        for e in page["StackEvents"]
    ]
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["Instance"], (
        f"expected exactly the instance to fail creation; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _REASON.match(reason)
    assert match is not None, f"the instance failure reason is not an EC2 error: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler_code"])
    want_error = (
        f"Could not find the specified version {_ABSENT_VERSION} for the launch template with "
        f"ID {lt_id}.",
        "Ec2",
        "400",
        "InvalidRequest",
    )
    assert got_error == want_error, (
        f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack_id)["StackResourceSummaries"]
    instance_ids = [
        r.get("PhysicalResourceId") for r in resources if r["LogicalResourceId"] == "Instance"
    ]
    assert instance_ids == [None], (
        f"a stack whose instance failed creation must list no instance physical id, got "
        f"{instance_ids!r}"
    )
    launched = _stack_instances(ec2, bad_stack_id)
    assert launched == [], f"the rolled-back stack launched instances {launched!r}; expected none"
    _delete_stack_and_wait(cfn, bad_stack_id)

    # Positive control: the launch template's own existing version launches an instance.
    good_stack_name = ctx.unique_name("sim2real-xsvc-ltverinstok-")
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=json.dumps(_template(lt_id, "1")),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": good_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))

    good_stack = _wait_create(ctx, cfn, good_stack_id)
    assert good_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the same launch template's existing version 1 ended {good_stack['StackStatus']!r} "
        f"({good_stack.get('StackStatusReason')!r}), expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good_stack.get("Outputs", [])}
    good_instance_id = outputs["InstanceId"]
    good_inst = _poll(
        ctx,
        f"instance {good_instance_id} running",
        lambda: ec2.describe_instances(InstanceIds=[good_instance_id])["Reservations"][0][
            "Instances"
        ][0],
        lambda i: i["State"]["Name"] == "running",
        300.0,
    )
    assert good_inst["InstanceType"] == instance_type, (
        f"the control instance reports type {good_inst['InstanceType']!r}, expected the launch "
        f"template's {instance_type!r}"
    )
    tagged = _stack_instances(ec2, good_stack_id)
    assert tagged == [good_instance_id], (
        f"instances tagged with the control stack's id are {tagged!r}, expected "
        f"{[good_instance_id]!r}"
    )

    _delete_stack_and_wait(cfn, good_stack_id)


def _al2023_ami(ec2) -> str:
    """The current AL2023 x86_64 AMI id Amazon owns, so ``create_launch_template`` needs no SSM
    client of its own."""
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )["Images"]
    assert images, "no available AL2023 x86_64 AMI found"
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
