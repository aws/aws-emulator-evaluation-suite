"""cfn-autoscaling-group-in-place-max-size-retained-replacement-enforces-bounds-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-autoscaling-group-in-place-max-size-retained-replacement-enforces-bounds-then-not-found"
)
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 300.0
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
INSTANCE_TYPE = "t3.nano"


def _above_max(desired: int, max_size: int) -> tuple[str, str]:
    """Auto Scaling's refusal of a desired capacity above the group's MaxSize."""
    return (
        "ValidationError",
        f"New SetDesiredCapacity value {desired} is above max value {max_size} for the "
        "AutoScalingGroup.",
    )


#: Auto Scaling's refusal to delete a group that does not exist, a template for its name.
_GROUP_NOT_FOUND = (
    "ValidationError",
    "AutoScalingGroup name not found - AutoScalingGroup '{name}' not found",
)

#: EC2's refusal of a launch template id that no longer exists.
_LT_NOT_FOUND = (
    "InvalidLaunchTemplateId.NotFound",
    "At least one of the launch templates specified in the request does not exist.",
)


def _template(
    group_name: str, max_size: int, role: str, subnet: str, group: str, ami: str | None = None
) -> str:
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
                "Lt": {
                    "Type": "AWS::EC2::LaunchTemplate",
                    "Properties": {
                        "LaunchTemplateData": {
                            "ImageId": {"Ref": "Ami"} if ami is None else ami,
                            "InstanceType": INSTANCE_TYPE,
                            # The shared subnets map public addresses; an instance never gets one.
                            "NetworkInterfaces": [
                                {
                                    "DeviceIndex": 0,
                                    "AssociatePublicIpAddress": False,
                                    "Groups": [group],
                                    "DeleteOnTermination": True,
                                }
                            ],
                        },
                    },
                },
                "Group": {
                    "Type": "AWS::AutoScaling::AutoScalingGroup",
                    # AutoScalingGroupName is create-only, so changing it replaces the group;
                    # MaxSize and Tags update in place.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "AutoScalingGroupName": group_name,
                        "MinSize": "0",
                        "MaxSize": str(max_size),
                        "DesiredCapacity": "0",
                        "VPCZoneIdentifier": [subnet],
                        "LaunchTemplate": {
                            "LaunchTemplateId": {"Ref": "Lt"},
                            "Version": {"Fn::GetAtt": ["Lt", "LatestVersionNumber"]},
                        },
                        "Tags": [{"Key": "Role", "Value": role, "PropagateAtLaunch": False}],
                    },
                },
            },
            "Outputs": {
                "GroupName": {"Value": {"Ref": "Group"}},
                "LaunchTemplateId": {"Value": {"Ref": "Lt"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation Auto Scaling group reads back as templated and enforces its MaxSize.

    A MaxSize and Tags change keeps the group and moves the bound SetDesiredCapacity is held to; an
    AutoScalingGroupName change under UpdateReplacePolicy Retain keeps the old group; delete: gone.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html
    """
    cfn = ctx.client("cloudformation")
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    zone, subnet = _zone_and_subnet(ctx, ec2)
    group = ctx.network().security_group_id
    first = ctx.unique_name("sim2real-cfnasg-a-")
    second = ctx.unique_name("sim2real-cfnasg-b-")
    stack_name = ctx.unique_name("sim2real-cfnasg-stack-")
    ref = {"stack": stack_name}

    # The replaced group is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_group(autoscaling, first))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # ---- 1. create: CloudFormation's view, Auto Scaling's view, and the MaxSize bound
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, 1, "blue", subnet, group), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    assert ids["Group"] == first, f"the group's physical id {ids['Group']!r} must be its name"
    lt_id = ids["Lt"]
    ami = next(p["ResolvedValue"] for p in stack["Parameters"] if p["ParameterKey"] == "Ami")
    assert ami.startswith("ami-"), f"the Ami parameter resolved to {ami!r}"
    assert lt_id.startswith("lt-"), f"the launch template's physical id {lt_id!r} must be its id"
    lt_name = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0][
        "LaunchTemplateName"
    ]
    assert _outputs(stack) == {"GroupName": first, "LaunchTemplateId": lt_id}, (
        f"outputs {_outputs(stack)!r}"
    )
    want = _group_view(first, 1, zone, subnet, lt_id, lt_name)
    _assert_group(ctx, autoscaling, first, want, _tag_rows(stack, first, "blue"))
    _assert_bounded(autoscaling, first, 1)

    # ---- 2. in-place: a larger MaxSize and a new tag value, the same group
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, 2, "green", subnet, group, ami),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Group"] == first, "an in-place update keeps the group"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Group"), first, "Group")
    want = _group_view(first, 2, zone, subnet, lt_id, lt_name)
    _assert_group(ctx, autoscaling, first, want, _tag_rows(stack, first, "green"))
    _assert_bounded(autoscaling, first, 2)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new group, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, 2, "green", subnet, group, ami),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Group"] == second, (
        f"the replacement must be the group {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Group"), first, second, "Group"
    )
    assert _outputs(stack) == {"GroupName": second, "LaunchTemplateId": lt_id}, (
        f"outputs after the replacement {_outputs(stack)!r}"
    )
    want = _group_view(second, 2, zone, subnet, lt_id, lt_name)
    _assert_group(ctx, autoscaling, second, want, _tag_rows(stack, second, "green"))
    _assert_bounded(autoscaling, second, 2)
    want = _group_view(first, 2, zone, subnet, lt_id, lt_name)
    _assert_group(ctx, autoscaling, first, want, _tag_rows(stack, first, "green"))
    _assert_bounded(autoscaling, first, 2)

    # ---- 4. delete: Auto Scaling no longer lists the stack's group, EC2 no longer knows its
    # launch template, and the retained group stays
    _delete_stack(ctx, cfn, ref["stack"])
    _wait_group_gone(ctx, autoscaling, second)
    got = _wait_error(
        ctx,
        lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id]),
        _LT_NOT_FOUND[0],
        f"launch template {lt_id}",
    )
    code, message = got
    assert (code, message) == _LT_NOT_FOUND, f"DescribeLaunchTemplates after the delete: {got!r}"
    assert [g["AutoScalingGroupName"] for g in _groups(autoscaling, first)] == [first], (
        f"the retained group {first!r} must outlive the stack delete"
    )


def _zone_and_subnet(ctx, ec2) -> tuple[str, str]:
    """The first shared-network (zone, subnet) whose zone offers the instance type."""
    network = ctx.network()
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = [z for z in network.availability_zones if z in offered]
    assert usable, f"no zone of {network.availability_zones!r} offers {INSTANCE_TYPE}"
    return usable[0], network.subnets[usable[0]]


def _group_view(name, max_size, zone, subnet, lt_id, lt_name) -> dict:
    return {
        "AutoScalingGroupName": name,
        "MinSize": 0,
        "MaxSize": max_size,
        "DesiredCapacity": 0,
        "Instances": [],
        "AvailabilityZones": [zone],
        "VPCZoneIdentifier": subnet,
        "LaunchTemplate": {
            "LaunchTemplateId": lt_id,
            "LaunchTemplateName": lt_name,
            "Version": "1",
        },
    }


def _tag_rows(stack: dict, group: str, role: str) -> list[tuple]:
    """The group's tags, sorted: its own, the stack's, and CloudFormation's aws: tags."""
    rows = [
        ("Role", role, False),
        ("sim2real", CHECK, True),
        ("aws:cloudformation:stack-name", stack["StackName"], True),
        ("aws:cloudformation:stack-id", stack["StackId"], True),
        ("aws:cloudformation:logical-id", "Group", True),
    ]
    return sorted((group, "auto-scaling-group", k, v, p) for k, v, p in rows)


def _groups(autoscaling, name: str) -> list[dict]:
    return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
        "AutoScalingGroups"
    ]


def _assert_group(ctx, autoscaling, name: str, want: dict, want_tags: list[tuple]) -> None:
    """DescribeAutoScalingGroups reports the template's properties and tags exactly.

    The read is polled so an update reaches every read before it is graded.
    """
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        groups = _groups(autoscaling, name)
        got, got_tags = None, None
        if len(groups) == 1:
            group = groups[0]
            got = {key: group.get(key) for key in want}
            got_tags = sorted(
                (t["ResourceId"], t["ResourceType"], t["Key"], t["Value"], t["PropagateAtLaunch"])
                for t in group.get("Tags", [])
            )
        if (got, got_tags) == (want, want_tags):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before group {name} showed {want!r}")
            raise AssertionError(
                f"DescribeAutoScalingGroups {name}: {got!r} tags {got_tags!r}, expected {want!r} "
                f"tags {want_tags!r}"
            )
        time.sleep(_POLL_S)


def _assert_bounded(autoscaling, name: str, max_size: int) -> None:
    """The group refuses a desired capacity above MaxSize and accepts its current zero."""
    got = _error(
        lambda: autoscaling.set_desired_capacity(
            AutoScalingGroupName=name, DesiredCapacity=max_size + 1
        )
    )
    assert got == _above_max(max_size + 1, max_size), (
        f"SetDesiredCapacity {max_size + 1} on {name} answered {got!r}"
    )
    autoscaling.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)
    group = _groups(autoscaling, name)[0]
    assert (group["DesiredCapacity"], group["Instances"]) == (0, []), (
        f"SetDesiredCapacity 0 on {name} left DesiredCapacity {group['DesiredCapacity']!r} and "
        f"instances {group['Instances']!r}"
    )


def _wait_group_gone(ctx, autoscaling, name: str) -> None:
    """Poll DescribeAutoScalingGroups until it no longer lists the group (deletion is async)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        groups = _groups(autoscaling, name)
        if groups == []:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while group {name} was still listed")
            raise AssertionError(
                f"group {name} still listed {timeout:.0f}s after its delete: "
                f"{[g.get('Status') for g in groups]!r}"
            )
        time.sleep(_POLL_S)


def _delete_group(autoscaling, name: str) -> None:
    """Delete the retained group with any instances; Auto Scaling finishes the delete itself."""
    if not _groups(autoscaling, name):
        return
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        err = exc.response["Error"]
        code, message = _GROUP_NOT_FOUND
        if (err["Code"], err.get("Message")) != (code, message.format(name=name)):
            raise


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


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
