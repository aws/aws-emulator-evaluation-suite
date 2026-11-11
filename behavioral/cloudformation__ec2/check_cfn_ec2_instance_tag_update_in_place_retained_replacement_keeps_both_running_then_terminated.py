"""cfn-ec2-instance-tag-update-in-place-retained-replacement-keeps-both-running-then-terminated."""

from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-ec2-instance-tag-update-in-place-retained-replacement-keeps-both-running-then-terminated"
)
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: EC2 tags and instance state are eventually consistent reads.
_PROPAGATE_CAP_S = 120.0
#: A terminating instance takes a minute or two to reach terminated.
_TERMINATE_CAP_S = 300.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
INSTANCE_TYPE = "t3.nano"
USER_DATA = base64.b64encode(b"#!/bin/bash\necho instance-check\n").decode()

#: EC2's state reason for an instance a TerminateInstances call shut down.
_USER_SHUTDOWN = {
    "Code": "Client.UserInitiatedShutdown",
    "Message": "Client.UserInitiatedShutdown: User initiated shutdown",
}
_INSTANCE_GONE = ("InvalidInstanceID.NotFound", "The instance ID '{instance_id}' does not exist")


def _template(name_tag: str, subnet: str, group: str, ami: str | None = None) -> str:
    """The stack template; *ami* pins the image the create resolved, so updates never move it."""
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Ami": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": AMI_PARAMETER,
            },
        },
    }
    if ami is not None:
        del body["Parameters"]
    return json.dumps(
        {
            **body,
            "Resources": {
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    # NetworkInterfaces is create-only, so moving the interface to another
                    # subnet replaces the instance; Tags update with no interruption.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ImageId": {"Ref": "Ami"} if ami is None else ami,
                        "InstanceType": INSTANCE_TYPE,
                        "NetworkInterfaces": [
                            {
                                "DeviceIndex": "0",
                                "SubnetId": subnet,
                                "GroupSet": [group],
                                "AssociatePublicIpAddress": False,
                                "DeleteOnTermination": True,
                            }
                        ],
                        "UserData": USER_DATA,
                        "Tags": [{"Key": "Name", "Value": name_tag}],
                    },
                },
            },
            "Outputs": {
                "InstanceId": {"Value": {"Ref": "Instance"}},
                "AvailabilityZone": {"Value": {"Fn::GetAtt": ["Instance", "AvailabilityZone"]}},
                "PrivateIp": {"Value": {"Fn::GetAtt": ["Instance", "PrivateIp"]}},
                "VpcId": {"Value": {"Fn::GetAtt": ["Instance", "VpcId"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation instance runs as templated, with its user data readable from EC2.

    A Tags change updates it in place without a restart; a subnet change under
    UpdateReplacePolicy Retain runs a new instance and keeps the old one; delete terminates it.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    (zone_a, subnet_a), (zone_b, subnet_b) = _two_zones(ec2, network)
    group = network.security_group_id
    first_tag = ctx.unique_name("sim2real-cfninst-a-")
    second_tag = ctx.unique_name("sim2real-cfninst-b-")
    stack_name = ctx.unique_name("sim2real-cfninst-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced instance is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _terminate(ec2, retained.get("id")))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # ---- 1. create: CloudFormation's view, EC2's view, and the running instance's attributes
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first_tag, subnet_a, group), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    first_id = _physical_ids(cfn, ref["stack"])["Instance"]
    retained["id"] = first_id
    ami = next(p["ResolvedValue"] for p in stack["Parameters"] if p["ParameterKey"] == "Ami")
    first = _assert_instance(
        ctx,
        ec2,
        first_id,
        ami=ami,
        zone=zone_a,
        subnet=subnet_a,
        vpc=network.vpc_id,
        group=group,
        tags=_tag_map(stack, first_tag),
    )
    assert _outputs(stack) == _instance_outputs(first, zone_a), f"outputs {_outputs(stack)!r}"
    _assert_attributes(ctx, ec2, first_id)

    # ---- 2. in-place: a new Name tag, the same instance, never stopped
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second_tag, subnet_a, group, ami), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Instance"] == first_id, (
        "an in-place update keeps the instance"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Instance"), first_id, "Instance")
    updated = _assert_instance(
        ctx,
        ec2,
        first_id,
        ami=ami,
        zone=zone_a,
        subnet=subnet_a,
        vpc=network.vpc_id,
        group=group,
        tags=_tag_map(stack, second_tag),
    )
    assert updated["LaunchTime"] == first["LaunchTime"], (
        f"a Tags update must not restart the instance: LaunchTime {first['LaunchTime']!r} became "
        f"{updated['LaunchTime']!r}"
    )

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new instance, the old one kept running
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second_tag, subnet_b, group, ami), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Instance"]
    assert second_id != first_id, f"the replacement must be a new instance, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Instance"), first_id, second_id, "Instance"
    )
    second = _assert_instance(
        ctx,
        ec2,
        second_id,
        ami=ami,
        zone=zone_b,
        subnet=subnet_b,
        vpc=network.vpc_id,
        group=group,
        tags=_tag_map(stack, second_tag),
    )
    assert _outputs(stack) == _instance_outputs(second, zone_b), (
        f"outputs after the replacement {_outputs(stack)!r}"
    )
    _assert_attributes(ctx, ec2, second_id)
    kept = _assert_instance(
        ctx,
        ec2,
        first_id,
        ami=ami,
        zone=zone_a,
        subnet=subnet_a,
        vpc=network.vpc_id,
        group=group,
        tags=_tag_map(stack, second_tag),
    )
    assert kept["LaunchTime"] == first["LaunchTime"], (
        f"the retained instance must keep running: LaunchTime {first['LaunchTime']!r} became "
        f"{kept['LaunchTime']!r}"
    )

    # ---- 4. delete: the stack's instance is terminated by the user; the retained one runs on
    _delete_stack(ctx, cfn, ref["stack"])
    gone = _wait_state(ctx, ec2, second_id, "terminated", _TERMINATE_CAP_S)
    assert gone.get("StateReason") == _USER_SHUTDOWN, (
        f"the stack's instance {second_id} ended with StateReason {gone.get('StateReason')!r}, "
        f"expected {_USER_SHUTDOWN!r}"
    )
    assert _describe(ec2, first_id)["State"]["Name"] == "running", (
        f"the retained instance {first_id} must outlive the stack delete"
    )


def _two_zones(ec2, network) -> list[tuple[str, str]]:
    """The first two shared-network (zone, subnet) pairs whose zone offers the instance type."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = [(z, network.subnets[z]) for z in network.availability_zones if z in offered]
    assert len(usable) >= 2, (
        f"fewer than two zones of {network.availability_zones!r} offer {INSTANCE_TYPE}"
    )
    return usable[:2]


def _tag_map(stack: dict, name_tag: str) -> dict[str, str]:
    """The tags CloudFormation puts on the instance: its own, the stack's and its aws: tags."""
    return {
        "Name": name_tag,
        "sim2real": CHECK,
        "aws:cloudformation:stack-name": stack["StackName"],
        "aws:cloudformation:stack-id": stack["StackId"],
        "aws:cloudformation:logical-id": "Instance",
    }


def _instance_outputs(inst: dict, zone: str) -> dict[str, str]:
    return {
        "InstanceId": inst["InstanceId"],
        "AvailabilityZone": zone,
        "PrivateIp": inst["PrivateIpAddress"],
        "VpcId": inst["VpcId"],
    }


def _describe(ec2, instance_id: str) -> dict:
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _assert_instance(ctx, ec2, instance_id: str, *, ami, zone, subnet, vpc, group, tags) -> dict:
    """DescribeInstances reports a running instance with the template's properties exactly.

    The read is polled: EC2's instance state and tags are eventually consistent.
    """
    want = {
        "State": "running",
        "ImageId": ami,
        "InstanceType": INSTANCE_TYPE,
        "AvailabilityZone": zone,
        "SubnetId": subnet,
        "VpcId": vpc,
        "SecurityGroups": [group],
        "PublicIpAddress": None,
        "Tags": tags,
    }
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        inst = _describe(ec2, instance_id)
        got = {
            "State": inst["State"]["Name"],
            "ImageId": inst.get("ImageId"),
            "InstanceType": inst.get("InstanceType"),
            "AvailabilityZone": inst.get("Placement", {}).get("AvailabilityZone"),
            "SubnetId": inst.get("SubnetId"),
            "VpcId": inst.get("VpcId"),
            "SecurityGroups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
            "PublicIpAddress": inst.get("PublicIpAddress"),
            "Tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
        }
        if got == want:
            return inst
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {instance_id} showed {want!r}")
            raise AssertionError(f"DescribeInstances {instance_id}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _assert_attributes(ctx, ec2, instance_id: str) -> None:
    """DescribeInstanceAttribute serves the instance's user data and launch settings (polled)."""

    def attribute(name: str, key: str):
        return ec2.describe_instance_attribute(InstanceId=instance_id, Attribute=name)[key]

    def read():
        return {
            "userData": attribute("userData", "UserData").get("Value"),
            "instanceType": attribute("instanceType", "InstanceType").get("Value"),
            "instanceInitiatedShutdownBehavior": attribute(
                "instanceInitiatedShutdownBehavior", "InstanceInitiatedShutdownBehavior"
            ).get("Value"),
            "disableApiTermination": attribute(
                "disableApiTermination", "DisableApiTermination"
            ).get("Value"),
        }

    want = {
        "userData": USER_DATA,
        "instanceType": INSTANCE_TYPE,
        "instanceInitiatedShutdownBehavior": "stop",
        "disableApiTermination": False,
    }
    got = _poll(ctx, read, want, f"DescribeInstanceAttribute {instance_id}")
    assert got == want, f"DescribeInstanceAttribute {instance_id}: {got!r}, expected {want!r}"


def _wait_state(ctx, ec2, instance_id: str, state: str, cap_s: float) -> dict:
    """Poll DescribeInstances until the instance is in *state*; the instance as last read."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        inst = _describe(ec2, instance_id)
        if inst["State"]["Name"] == state:
            return inst
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {instance_id} was {inst['State']!r}")
            raise AssertionError(
                f"{instance_id} still {inst['State']['Name']!r} after {timeout:.0f}s, "
                f"expected {state!r}"
            )
        time.sleep(_POLL_S)


def _terminate(ec2, instance_id: str | None) -> None:
    """Terminate the retained instance and wait, with a fixed cap, until EC2 reports it terminated.

    Waiting frees its network interface before the shared network is torn down.
    """
    if instance_id is None:
        return
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        # A refused terminate passes only once DescribeInstances answers the exact not-found pair.
        try:
            ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as gone:
            err = gone.response["Error"]
            want = (_INSTANCE_GONE[0], _INSTANCE_GONE[1].format(instance_id=instance_id))
            if (err["Code"], err.get("Message")) == want:
                return
            raise exc from gone
        raise
    _wait_state(None, ec2, instance_id, "terminated", _TERMINATE_CAP_S)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap, since the body's deadline does not bound the cleanup.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Registered with ``ctx=None`` so its waits take their full caps after the body's deadline.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


def _poll(ctx, read, want, what: str):
    """Poll ``read()`` until it returns *want* (EC2 reads are eventually consistent).

    A ClientError while polling is retried; the last answer is named when the cap ends.
    """
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        try:
            got = read()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = ("error", err.get("Code"), err.get("Message"))
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {what} showed {want!r}")
            raise AssertionError(f"{what}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
