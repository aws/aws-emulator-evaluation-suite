"""cfn-ec2-route-retarget-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-route-retarget-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.85.0.0/16"
_SUBNET_CIDR = "10.85.1.0/24"
#: Documentation ranges (RFC 5737) as destinations: the routes are exact and reach no real peer.
_FIRST_DEST = "203.0.113.0/24"
_SECOND_DEST = "198.51.100.0/24"
_LOCAL = {
    "DestinationCidrBlock": _VPC_CIDR,
    "GatewayId": "local",
    "Origin": "CreateRouteTable",
    "State": "active",
}
_ROUTE_KEYS = (
    "DestinationCidrBlock",
    "GatewayId",
    "NetworkInterfaceId",
    "InstanceId",
    "Origin",
    "State",
)

#: EC2's refusal of a route table that no longer exists.
_NOT_FOUND = ("InvalidRouteTableID.NotFound", "The routeTable ID '{}' does not exist")


def _template(az: str, dest: str, via_eni: bool) -> str:
    target = {"NetworkInterfaceId": {"Ref": "Eni"}} if via_eni else {"GatewayId": {"Ref": "Igw"}}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": _TAGS}},
                "Attachment": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": _SUBNET_CIDR,
                        "AvailabilityZone": az,
                        "Tags": _TAGS,
                    },
                },
                "Eni": {
                    "Type": "AWS::EC2::NetworkInterface",
                    "Properties": {"SubnetId": {"Ref": "Subnet"}, "Tags": _TAGS},
                },
                "RouteTable": {
                    "Type": "AWS::EC2::RouteTable",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": _TAGS},
                },
                "Route": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "Attachment",
                    # DestinationCidrBlock is create-only, so changing it replaces the route; the
                    # target properties update in place.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "RouteTableId": {"Ref": "RouteTable"},
                        "DestinationCidrBlock": dest,
                        **target,
                    },
                },
            },
            "Outputs": {"RouteCidr": {"Value": {"Fn::GetAtt": ["Route", "CidrBlock"]}}},
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation route is an active route to the attached gateway in its table.

    Retargeting it to a network interface rewrites the same route in place; a destination change
    under UpdateReplacePolicy Retain keeps both routes; delete: InvalidRouteTableID.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-route.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)
    stack_name = ctx.unique_name("sim2real-cfnrte-")
    ref = {"stack": stack_name}
    retained: dict[str, str] = {}

    # The replaced route is retained and targets the stack's network interface, so it is
    # deleted before the stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))
    ctx.on_cleanup(lambda: _delete_route(ec2, retained.get("rtb"), _FIRST_DEST))

    # ---- 1. create: CloudFormation's view and the route table's view of the route
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(az, _FIRST_DEST, False), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    rt_id, igw_id, eni_id, first_id = ids["RouteTable"], ids["Igw"], ids["Eni"], ids["Route"]
    assert _outputs(stack) == {"RouteCidr": _FIRST_DEST}, f"GetAtt outputs {_outputs(stack)!r}"
    via_igw = _route(_FIRST_DEST, GatewayId=igw_id, State="active")
    # The route does its job: the table forwards the destination to the attached gateway.
    _assert_routes(ctx, ec2, rt_id, [via_igw])

    # ---- 2. in-place: the same route, now to the network interface
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(az, _FIRST_DEST, True), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Route"] == first_id, (
        "an in-place update keeps the route"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Route"), first_id, "Route")
    # An interface attached to no instance cannot carry traffic, so EC2 marks the route blackhole.
    first_via_eni = _route(_FIRST_DEST, NetworkInterfaceId=eni_id, State="blackhole")
    _assert_routes(ctx, ec2, rt_id, [first_via_eni])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new route, the old one kept
    # Registered before the update: CloudFormation may retain the old one before the poll ends.
    retained["rtb"] = rt_id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(az, _SECOND_DEST, True), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Route"]
    assert second_id != first_id, f"the replacement must be a new route, still {first_id!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Route"), first_id, second_id, "Route"
    )
    assert _outputs(stack) == {"RouteCidr": _SECOND_DEST}, f"GetAtt outputs {_outputs(stack)!r}"
    second_via_eni = _route(_SECOND_DEST, NetworkInterfaceId=eni_id, State="blackhole")
    _assert_routes(ctx, ec2, rt_id, [first_via_eni, second_via_eni])

    # ---- 4. delete: the retained route by hand, then the stack with its table
    ec2.delete_route(RouteTableId=rt_id, DestinationCidrBlock=_FIRST_DEST)
    _assert_routes(ctx, ec2, rt_id, [second_via_eni])
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: ec2.describe_route_tables(RouteTableIds=[rt_id]),
        _NOT_FOUND[0],
        f"route table {rt_id}",
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(rt_id)), (
        f"DescribeRouteTables after the stack delete answered {got!r}"
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


def _route(dest: str, **fields) -> dict:
    """A CreateRoute route as DescribeRouteTables projects it onto _ROUTE_KEYS."""
    full = {"DestinationCidrBlock": dest, "Origin": "CreateRoute", **fields}
    return {k: full.get(k) for k in _ROUTE_KEYS}


def _assert_routes(ctx, ec2, rt_id: str, routes: list[dict]) -> None:
    """The table holds its local route and exactly *routes*, ordered by destination."""
    local = {k: _LOCAL.get(k) for k in _ROUTE_KEYS}

    def read() -> list[dict]:
        got = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
        return sorted(
            ({k: r.get(k) for k in _ROUTE_KEYS} for r in got),
            key=lambda r: r["DestinationCidrBlock"] or "",
        )

    want = sorted([local, *routes], key=lambda r: r["DestinationCidrBlock"])
    _wait_for(ctx, read, want, f"routes of {rt_id}")


def _delete_route(ec2, rt_id: str | None, dest: str) -> None:
    if rt_id is None:
        return
    try:
        ec2.delete_route(RouteTableId=rt_id, DestinationCidrBlock=dest)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidRoute.NotFound", _NOT_FOUND[0]):
            raise


# ===== helpers =====


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
