"""cfn-ec2-internet-gateway-tag-update-in-place-attached-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-internet-gateway-tag-update-in-place-attached-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.86.0.0/16"
_DEFAULT_ROUTE = "0.0.0.0/0"

#: EC2's refusal of an internet gateway that no longer exists.
_NOT_FOUND = ("InvalidInternetGatewayID.NotFound", "The internetGateway ID '{}' does not exist")


def _template(name: str) -> str:
    # Tags are AWS::EC2::InternetGateway's only property and update in place, so the type has no
    # replacement to exercise.
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                "Igw": {
                    "Type": "AWS::EC2::InternetGateway",
                    "Properties": {"Tags": _TAGS + [{"Key": "Name", "Value": name}]},
                },
                "Attachment": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
                },
                "RouteTable": {
                    "Type": "AWS::EC2::RouteTable",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": _TAGS},
                },
                "DefaultRoute": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "Attachment",
                    "Properties": {
                        "RouteTableId": {"Ref": "RouteTable"},
                        "DestinationCidrBlock": _DEFAULT_ROUTE,
                        "GatewayId": {"Ref": "Igw"},
                    },
                },
            },
            "Outputs": {"IgwId": {"Value": {"Fn::GetAtt": ["Igw", "InternetGatewayId"]}}},
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation internet gateway is attached to its VPC and an active route target.

    A Name tag change updates the same gateway in place and keeps it attached; delete:
    InvalidInternetGatewayID.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-internetgateway.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnigw-")
    first = ctx.unique_name("sim2real-cfnigw-a-")
    second = ctx.unique_name("sim2real-cfnigw-b-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, EC2's view, and the gateway serving the VPC
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_id, igw_id, rt_id = ids["Vpc"], ids["Igw"], ids["RouteTable"]
    assert _outputs(stack) == {"IgwId": igw_id}, f"GetAtt outputs {_outputs(stack)!r}"
    stamped = _stack_tags(stack_name, ref["stack"], "Igw")
    _assert_gateway(ctx, ec2, igw_id, vpc_id, {"sim2real": CHECK, "Name": first, **stamped})
    # The gateway does its job: the table's default route through it is active.
    _assert_default_route(ctx, ec2, rt_id, igw_id)

    # ---- 2. in-place: a new Name tag, the same gateway, still attached
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Igw"] == igw_id, "an in-place update keeps the gateway"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Igw"), igw_id, "Igw")
    _assert_gateway(ctx, ec2, igw_id, vpc_id, {"sim2real": CHECK, "Name": second, **stamped})
    _assert_default_route(ctx, ec2, rt_id, igw_id)

    # ---- 3. delete: the stack detaches and deletes the gateway
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]),
        _NOT_FOUND[0],
        f"internet gateway {igw_id}",
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(igw_id)), (
        f"DescribeInternetGateways after the stack delete answered {got!r}"
    )


def _assert_gateway(ctx, ec2, igw_id: str, vpc_id: str, tags_want: dict) -> None:
    def read() -> dict:
        g = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][0]
        return {"Attachments": g.get("Attachments"), "Tags": _tag_map(g.get("Tags"))}

    want = {"Attachments": [{"State": "available", "VpcId": vpc_id}], "Tags": tags_want}
    _wait_for(ctx, read, want, f"DescribeInternetGateways {igw_id}")


def _assert_default_route(ctx, ec2, rt_id: str, igw_id: str) -> None:
    want = [
        {
            "DestinationCidrBlock": _DEFAULT_ROUTE,
            "GatewayId": igw_id,
            "Origin": "CreateRoute",
            "State": "active",
        }
    ]
    _wait_for(
        ctx,
        lambda: [
            r
            for r in ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
            if r.get("DestinationCidrBlock") == _DEFAULT_ROUTE
        ],
        want,
        f"default route of {rt_id}",
    )


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
