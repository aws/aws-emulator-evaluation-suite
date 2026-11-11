"""cfn-ec2-subnet-route-table-association-replace-deletes-first-despite-retain-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-subnet-route-table-association-replace-deletes-first-despite-retain-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.88.0.0/16"
_CIDRS = {"SubnetA": "10.88.1.0/24", "SubnetB": "10.88.2.0/24"}

#: CloudFormation's reason for a replacement that deletes the old resource before creating the new.
_DELETE_FIRST = (
    "Requested update requires the replacement of the existing resource; deleting existing "
    "resource, then creating a new one."
)

#: EC2's refusal of a route table that no longer exists.
_NOT_FOUND = ("InvalidRouteTableID.NotFound", "The routeTable ID '{}' does not exist")


def _template(az: str, subnet: str) -> str:
    # Both properties of AWS::EC2::SubnetRouteTableAssociation are create-only, so the type has
    # no in-place update to exercise; a SubnetId change replaces the association. CloudFormation
    # deletes the old association before creating the new one, so UpdateReplacePolicy Retain
    # keeps nothing.
    subnets = {
        name: {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": cidr,
                "AvailabilityZone": az,
                "Tags": _TAGS,
            },
        }
        for name, cidr in _CIDRS.items()
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                **subnets,
                "RouteTable": {
                    "Type": "AWS::EC2::RouteTable",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": _TAGS},
                },
                "Association": {
                    "Type": "AWS::EC2::SubnetRouteTableAssociation",
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "SubnetId": {"Ref": subnet},
                        "RouteTableId": {"Ref": "RouteTable"},
                    },
                },
            },
            "Outputs": {"AssociationId": {"Value": {"Fn::GetAtt": ["Association", "Id"]}}},
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation association makes its subnet resolve to the templated route table.

    A SubnetId change deletes the old association first, so UpdateReplacePolicy Retain keeps
    nothing and only the new subnet stays on the table; delete: InvalidRouteTableID.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnetroutetableassociation.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)
    stack_name = ctx.unique_name("sim2real-cfnrta-")
    ref = {"stack": stack_name}
    retained: dict[str, str] = {}

    # Should a replaced association outlive the update it would pin the stack's route table,
    # so it is removed before the stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))
    ctx.on_cleanup(lambda: _disassociate(ec2, retained.get("id")))

    # ---- 1. create: CloudFormation's view and which table each subnet resolves to
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(az, "SubnetA"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    rt_id, subnet_a, subnet_b, first_id = (
        ids["RouteTable"],
        ids["SubnetA"],
        ids["SubnetB"],
        ids["Association"],
    )
    assert _outputs(stack) == {"AssociationId": first_id}, f"GetAtt outputs {_outputs(stack)!r}"
    # The association does its job: subnet A resolves to the stack's table, subnet B still
    # resolves to the VPC's main table (no explicit association).
    _assert_resolution(ctx, ec2, rt_id, {subnet_a: first_id})
    _assert_unassociated(ctx, ec2, subnet_b)

    # ---- 2. replacement under UpdateReplacePolicy Retain: delete first, so nothing is kept
    # Registered before the update, in case the old association outlives it.
    retained["id"] = first_id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(az, "SubnetB"), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_id = _physical_ids(cfn, ref["stack"])["Association"]
    assert second_id != first_id, f"the replacement must be a new association, still {first_id!r}"
    rows = _rows(_events(cfn, ref["stack"]), seen, "Association")
    want_rows = [
        ("UPDATE_IN_PROGRESS", None, first_id),
        ("DELETE_IN_PROGRESS", _DELETE_FIRST, first_id),
        ("DELETE_COMPLETE", f"Resource {first_id} delete complete", first_id),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated", second_id),
        ("CREATE_COMPLETE", None, second_id),
        ("UPDATE_COMPLETE", None, second_id),
    ]
    assert rows == want_rows, (
        f"Association must be deleted before its replacement is created, its events were {rows!r}"
    )
    assert _outputs(stack) == {"AssociationId": second_id}, f"GetAtt outputs {_outputs(stack)!r}"
    # The old association is gone: subnet A falls back to the main table, B uses the stack's.
    _assert_resolution(ctx, ec2, rt_id, {subnet_b: second_id})
    _assert_unassociated(ctx, ec2, subnet_a)

    # ---- 3. delete: the stack with its table
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


def _assert_resolution(ctx, ec2, rt_id: str, associated: dict[str, str]) -> None:
    """The table's associations are exactly *associated* (subnet -> association id).

    The association.subnet-id filter resolves each of those subnets to the table.
    """
    want = {
        "associations": sorted(
            (subnet, assoc, rt_id, False, "associated") for subnet, assoc in associated.items()
        ),
        "resolved": {subnet: [rt_id] for subnet in associated},
    }

    def read() -> dict:
        table = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
        resolved = {
            subnet: [
                t["RouteTableId"]
                for t in ec2.describe_route_tables(
                    Filters=[{"Name": "association.subnet-id", "Values": [subnet]}]
                )["RouteTables"]
            ]
            for subnet in associated
        }
        return {
            "associations": sorted(
                (
                    a.get("SubnetId"),
                    a.get("RouteTableAssociationId"),
                    a.get("RouteTableId"),
                    a.get("Main"),
                    a.get("AssociationState", {}).get("State"),
                )
                for a in table["Associations"]
            ),
            "resolved": resolved,
        }

    _wait_for(ctx, read, want, f"associations of {rt_id}")


def _assert_unassociated(ctx, ec2, subnet_id: str) -> None:
    """No route table names *subnet_id* explicitly, so it resolves to the VPC's main table."""
    _wait_for(
        ctx,
        lambda: ec2.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )["RouteTables"],
        [],
        f"route tables explicitly associated with {subnet_id}",
    )


def _disassociate(ec2, association_id: str | None) -> None:
    if association_id is None:
        return
    try:
        ec2.disassociate_route_table(AssociationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAssociationID.NotFound":
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
