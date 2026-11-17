"""cfn-ec2-subnet-cidr-reservation-tag-update-in-place-description-change-replaces-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-subnet-cidr-reservation-tag-update-in-place-description-change-replaces-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.92.0.0/16"
_SUBNET_CIDR = "10.92.1.0/24"
_RESERVED_CIDR = "10.92.1.128/28"

#: EC2's refusal of a subnet CIDR reservation, and a subnet, that no longer exist.
_NOT_FOUND = ("InvalidSubnetCidrReservationID.NotFound", "The subnet-cidr-reservation ID '{}' does not exist")
_SUBNET_NOT_FOUND = ("InvalidSubnetID.NotFound", "The subnet ID '{}' does not exist")


def _template(name: str, description: str) -> str:
    # ReservationType and SubnetId are create-only too, but Description is the cheapest
    # create-only property to flip without touching the reserved range itself, so changing it
    # isolates the replacement path from any CIDR-allocation side effect.
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
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": _SUBNET_CIDR,
                        "Tags": _TAGS,
                    },
                },
                "Reservation": {
                    "Type": "AWS::EC2::SubnetCidrReservation",
                    "Properties": {
                        "SubnetId": {"Ref": "Subnet"},
                        "Cidr": _RESERVED_CIDR,
                        "ReservationType": "explicit",
                        "Description": description,
                        "Tags": [{"Key": "Name", "Value": name}],
                    },
                },
            },
            "Outputs": {
                "ReservationId": {"Value": {"Fn::GetAtt": ["Reservation", "SubnetCidrReservationId"]}},
            },
        }
    )


def _template_without_reservation() -> str:
    """The VPC and subnet alone, so removing the reservation from the stack leaves them in place."""
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
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": _SUBNET_CIDR,
                        "Tags": _TAGS,
                    },
                },
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation subnet CIDR reservation holds its CIDR out of EC2's auto-assignment.

    A Name tag change updates the same reservation in place; a Description change replaces it
    with a new reservation id; delete frees the CIDR entirely.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnetcidrreservation.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnscr-")
    first = ctx.unique_name("sim2real-cfnscr-a-")
    second = ctx.unique_name("sim2real-cfnscr-b-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view and EC2's view agree, and the CIDR is held
    ref["stack"], stack = _create_stack_past_vpc_contention(
        ctx, cfn, stack_name, _template(first, "first"), Tags=_TAGS
    )
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    subnet_id = ids["Subnet"]
    physical_id = ids["Reservation"]
    reservation_id = physical_id.rsplit("|", 1)[-1]
    assert physical_id == f"{subnet_id}|{reservation_id}", f"reservation physical id {physical_id!r}"
    assert _outputs(stack) == {"ReservationId": reservation_id}, f"GetAtt outputs {_outputs(stack)!r}"
    _assert_reservation(ctx, ec2, subnet_id, reservation_id, _RESERVED_CIDR, "first", {"Name": first})
    _assert_cidr_held(ec2, subnet_id, _RESERVED_CIDR)

    # ---- 2. in-place: a new Name tag, the same reservation
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, "first"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Reservation"] == physical_id, (
        "a Tags-only update keeps the same reservation"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Reservation"), physical_id, "Reservation")
    _assert_reservation(ctx, ec2, subnet_id, reservation_id, _RESERVED_CIDR, "first", {"Name": second})

    # ---- 3. replacement: a Description change forces a new reservation id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, "second"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    new_physical_id = _physical_ids(cfn, ref["stack"])["Reservation"]
    new_reservation_id = new_physical_id.rsplit("|", 1)[-1]
    assert new_physical_id != physical_id, "a Description change must replace the reservation"
    _assert_replaced(
        _rows(_events(cfn, ref["stack"]), seen, "Reservation"),
        physical_id,
        new_physical_id,
        "Reservation",
    )
    _assert_reservation(
        ctx, ec2, subnet_id, new_reservation_id, _RESERVED_CIDR, "second", {"Name": second}
    )
    _assert_gone(ctx, ec2, reservation_id)

    # ---- 4. delete the reservation alone: the CIDR is freed while the subnet lives on
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template_without_reservation(), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert set(_physical_ids(cfn, ref["stack"])) == {"Vpc", "Subnet"}, (
        "removing the reservation from the template must leave the VPC and subnet"
    )
    _assert_gone(ctx, ec2, new_reservation_id)
    reused = ec2.create_subnet_cidr_reservation(
        SubnetId=subnet_id, Cidr=_RESERVED_CIDR, ReservationType="explicit"
    )["SubnetCidrReservation"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_subnet_cidr_reservation(
        SubnetCidrReservationId=reused["SubnetCidrReservationId"]), _NOT_FOUND[0]))
    assert reused["Cidr"] == _RESERVED_CIDR, f"expected the freed CIDR to be reusable, got {reused!r}"

    # ---- 5. delete the stack: the subnet and VPC are gone too
    ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reused["SubnetCidrReservationId"])
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: ec2.describe_subnets(SubnetIds=[subnet_id]), _SUBNET_NOT_FOUND[0], subnet_id
    )
    assert got == (_SUBNET_NOT_FOUND[0], _SUBNET_NOT_FOUND[1].format(subnet_id)), (
        f"DescribeSubnets after the stack delete answered {got!r}"
    )


def _assert_cidr_held(ec2, subnet_id: str, cidr: str) -> None:
    """A second overlapping reservation is rejected while the stack's is held."""
    try:
        ec2.create_subnet_cidr_reservation(SubnetId=subnet_id, Cidr=cidr, ReservationType="explicit")
    except ClientError as exc:
        err = exc.response["Error"]
        expected_msg = f"Reservation CIDR {cidr} has overlap with existing reserved CIDR block"
        assert (err["Code"], err.get("Message")) == ("InvalidParameterValue", expected_msg), (
            f"expected (InvalidParameterValue, {expected_msg!r}) for an overlapping reservation, got {err!r}"
        )
        return
    raise AssertionError(f"a second reservation of the held CIDR {cidr!r} unexpectedly succeeded")


def _assert_reservation(
    ctx, ec2, subnet_id: str, reservation_id: str, cidr: str, description: str, extra_tags: dict
) -> None:
    def read() -> dict:
        rows = ec2.get_subnet_cidr_reservations(SubnetId=subnet_id)["SubnetIpv4CidrReservations"]
        match = [r for r in rows if r["SubnetCidrReservationId"] == reservation_id]
        if not match:
            return {}
        r = match[0]
        return {
            "Cidr": r.get("Cidr"),
            "ReservationType": r.get("ReservationType"),
            "Description": r.get("Description"),
            "Tags": _tag_map(r.get("Tags")),
        }

    want = {
        "Cidr": cidr,
        "ReservationType": "explicit",
        "Description": description,
        "Tags": {"sim2real": CHECK, **extra_tags},
    }
    _wait_for(ctx, read, want, f"GetSubnetCidrReservations {reservation_id}")


def _assert_gone(ctx, ec2, reservation_id: str) -> None:
    got = _wait_error(
        ctx,
        lambda: ec2.delete_subnet_cidr_reservation(SubnetCidrReservationId=reservation_id),
        _NOT_FOUND[0],
        f"subnet CIDR reservation {reservation_id}",
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(reservation_id)), (
        f"re-deleting {reservation_id} answered {got!r}"
    )


# ===== helpers =====


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _tag_map(tags_in: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags_in or []}


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


def _create_stack_past_vpc_contention(ctx, cfn, name: str, template: str, **kw):
    """CreateStack, retried if a sibling check's own VPC transiently fills the account's quota.

    The account's default VPC-per-Region limit is shared with whatever else runs concurrently in
    it; a rollback for that reason alone is retried rather than treated as this stack's outcome.
    """
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    while True:
        stack_id = cfn.create_stack(StackName=name, TemplateBody=template, **kw)["StackId"]
        stack = _settle(ctx, cfn, stack_id)
        if stack["StackStatus"] != "ROLLBACK_COMPLETE":
            return stack_id, stack
        reasons = [
            e.get("ResourceStatusReason") or ""
            for e in _events(cfn, stack_id)
            if e["ResourceStatus"] == "CREATE_FAILED"
        ]
        if not any("maximum number of VPCs" in r for r in reasons) or time.monotonic() >= deadline:
            return stack_id, stack
        _delete_stack(ctx, cfn, stack_id)
        time.sleep(5.0)


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


def _assert_replaced(rows: list[tuple], old_physical_id: str, new_physical_id: str, logical_id: str) -> None:
    """The replacement deletes *old_physical_id* and completes creation on *new_physical_id*."""
    old_events = [(status, pid) for status, _, pid in rows if pid == old_physical_id]
    new_events = [(status, pid) for status, _, pid in rows if pid == new_physical_id]
    assert ("DELETE_COMPLETE", old_physical_id) in old_events, (
        f"{logical_id}'s old resource {old_physical_id!r} was never deleted: {rows!r}"
    )
    assert ("CREATE_COMPLETE", new_physical_id) in new_events, (
        f"{logical_id}'s new resource {new_physical_id!r} was never created: {rows!r}"
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
    """Poll ``fn`` until it raises *code* (a delete can lag); returns (code, message)."""
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
