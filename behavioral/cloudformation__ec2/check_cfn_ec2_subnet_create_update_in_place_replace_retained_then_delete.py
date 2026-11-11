"""cfn-ec2-subnet-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-subnet-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.81.0.0/16"
_FIRST_CIDR = "10.81.1.0/24"
_SECOND_CIDR = "10.81.2.0/24"
#: AWS reserves the first four and the last address of every subnet: a /24 offers 251.
_FREE_IN_24 = 251

#: EC2's refusal of a subnet that no longer exists.
_NOT_FOUND = ("InvalidSubnetID.NotFound", "The subnet ID '{}' does not exist")


def _template(az: str, cidr: str, map_public_ip: bool) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    # CidrBlock is create-only, so changing it replaces the subnet.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": cidr,
                        "AvailabilityZone": az,
                        "MapPublicIpOnLaunch": map_public_ip,
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "SubnetId": {"Value": {"Fn::GetAtt": ["Subnet", "SubnetId"]}},
                "VpcId": {"Value": {"Fn::GetAtt": ["Subnet", "VpcId"]}},
                "AvailabilityZone": {"Value": {"Fn::GetAtt": ["Subnet", "AvailabilityZone"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation subnet reads back as templated with 251 free addresses and the main table.

    MapPublicIpOnLaunch updates in place; a CidrBlock change under UpdateReplacePolicy Retain keeps
    both subnets; delete: InvalidSubnetID.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)
    stack_name = ctx.unique_name("sim2real-cfnsub-")
    ref = {"stack": stack_name}
    retained: dict[str, str] = {}

    # The replaced subnet is retained inside the stack's VPC, so it is deleted before the stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))
    ctx.on_cleanup(lambda: _delete_subnet(ec2, retained.get("id")))

    # ---- 1. create: CloudFormation's view, EC2's view, and the subnet's route resolution
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(az, _FIRST_CIDR, False), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_id, first_id = ids["Vpc"], ids["Subnet"]
    assert _outputs(stack) == {"SubnetId": first_id, "VpcId": vpc_id, "AvailabilityZone": az}, (
        f"GetAtt outputs {_outputs(stack)!r}"
    )
    stamped = _stack_tags(stack_name, ref["stack"], "Subnet")
    _assert_subnet(ctx, ec2, first_id, vpc_id, az, _FIRST_CIDR, False, stamped)

    # The subnet does its job: with no explicit association it resolves to the VPC's main route
    # table, whose local route covers the subnet's addresses.
    _assert_routes_via_main(ctx, ec2, first_id, vpc_id)

    # ---- 2. in-place: MapPublicIpOnLaunch on, the same subnet
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(az, _FIRST_CIDR, True), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Subnet"] == first_id, (
        "an in-place update keeps the subnet"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Subnet"), first_id, "Subnet")
    _assert_subnet(ctx, ec2, first_id, vpc_id, az, _FIRST_CIDR, True, stamped)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new subnet, the old one kept
    # Registered before the update: CloudFormation may retain the old one before the poll ends.
    retained["id"] = first_id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(az, _SECOND_CIDR, True), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Subnet"]
    assert second_id != first_id, f"the replacement must be a new subnet, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Subnet"), first_id, second_id, "Subnet"
    )
    assert _outputs(stack)["SubnetId"] == second_id, f"GetAtt outputs {_outputs(stack)!r}"
    _assert_subnet(ctx, ec2, second_id, vpc_id, az, _SECOND_CIDR, True, stamped)
    _assert_subnet(ctx, ec2, first_id, vpc_id, az, _FIRST_CIDR, True, stamped)
    _assert_routes_via_main(ctx, ec2, second_id, vpc_id)

    # ---- 4. delete: the retained subnet by hand, then the stack; EC2 knows neither
    ec2.delete_subnet(SubnetId=first_id)
    _assert_gone(ctx, ec2, first_id)
    _delete_stack(ctx, cfn, ref["stack"])
    _assert_gone(ctx, ec2, second_id)


def _assert_gone(ctx, ec2, subnet_id: str) -> None:
    got = _wait_error(
        ctx,
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id]),
        _NOT_FOUND[0],
        f"subnet {subnet_id}",
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(subnet_id)), (
        f"DescribeSubnets {subnet_id} after its delete answered {got!r}"
    )


def _usable_az(ec2) -> str:
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _assert_subnet(ctx, ec2, subnet_id, vpc_id, az, cidr, map_public_ip, stamped) -> None:
    """DescribeSubnets reports the template's properties exactly (polled: EC2 is eventual)."""

    def read() -> dict:
        s = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        got = {
            k: s.get(k)
            for k in (
                "SubnetId",
                "VpcId",
                "CidrBlock",
                "AvailabilityZone",
                "State",
                "MapPublicIpOnLaunch",
                "DefaultForAz",
                "AvailableIpAddressCount",
            )
        }
        got["Tags"] = _tag_map(s.get("Tags"))
        return got

    want = {
        "SubnetId": subnet_id,
        "VpcId": vpc_id,
        "CidrBlock": cidr,
        "AvailabilityZone": az,
        "State": "available",
        "MapPublicIpOnLaunch": map_public_ip,
        "DefaultForAz": False,
        "AvailableIpAddressCount": _FREE_IN_24,
        "Tags": {"sim2real": CHECK, **stamped},
    }
    _wait_for(ctx, read, want, f"DescribeSubnets {subnet_id}")


def _assert_routes_via_main(ctx, ec2, subnet_id: str, vpc_id: str) -> None:
    """The subnet has no explicit association, so the main route table's local route serves it."""
    _wait_for(
        ctx,
        lambda: ec2.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )["RouteTables"],
        [],
        f"route tables explicitly associated with {subnet_id}",
    )
    local = {
        "DestinationCidrBlock": _VPC_CIDR,
        "GatewayId": "local",
        "Origin": "CreateRouteTable",
        "State": "active",
    }
    _wait_for(
        ctx,
        lambda: [
            t["Routes"]
            for t in ec2.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            )["RouteTables"]
        ],
        [[local]],
        f"routes of the main route tables of {vpc_id}, which {subnet_id} resolves to",
    )


def _delete_subnet(ec2, subnet_id: str | None) -> None:
    if subnet_id is None:
        return
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


# ===== helpers =====


def _tag_map(tags: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}


def _stack_tags(stack_name: str, stack_id: str, logical_id: str) -> dict[str, str]:
    """The tags CloudFormation itself stamps on an EC2 resource it creates."""
    return {
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": logical_id,
    }


def _wait_for(ctx, read, want, what: str):
    """Poll ``read()`` until it equals *want*: EC2 reads are eventually consistent."""
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = read()
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with {what} at {got!r}, expected {want!r}")
            raise AssertionError(f"{what}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. ctx=None (teardown) waits the full cap;
    in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
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
    quota = [reason for _, _, reason in failed if reason and "LimitExceeded" in reason]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
        + (f"; an account quota refused it, not the template: {quota!r}" if quota else "")
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


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits pass ctx=None, so a body that ran out of time still gets the full stack cap.
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
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
