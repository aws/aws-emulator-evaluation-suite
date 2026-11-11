"""cfn-ec2-vpc-gateway-attachment-swap-gateway-in-place-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-vpc-gateway-attachment-swap-gateway-in-place-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.87.0.0/16"

#: EC2's refusals of an internet gateway and of a VPC that no longer exist.
_IGW_NOT_FOUND = ("InvalidInternetGatewayID.NotFound", "The internetGateway ID '{}' does not exist")
_VPC_NOT_FOUND = ("InvalidVpcID.NotFound", "The vpc ID '{}' does not exist")


def _template(gateway: str) -> str:
    # VpcId is the attachment's only replacement-forcing property and needs a second VPC; the
    # check keeps to one VPC, so it exercises the in-place path (InternetGatewayId) only. The
    # template holds one gateway at a time, so the swap adds the new gateway and drops the old.
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS},
                },
                gateway: {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": _TAGS}},
                "Attachment": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": gateway}},
                },
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation gateway attachment leaves exactly its gateway attached to its VPC.

    Swapping InternetGatewayId keeps the attachment and moves the VPC to the new gateway; delete:
    the gateway and the VPC are NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcgatewayattachment.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnvga-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, EC2's view of which gateway serves the VPC
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template("IgwA"), Tags=_TAGS
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_id, first_igw, attachment = ids["Vpc"], ids["IgwA"], ids["Attachment"]
    # The attachment's physical id names the gateway kind and the VPC it joins.
    assert attachment == f"IGW|{vpc_id}", f"attachment physical id {attachment!r}"
    # The attachment does its job: the VPC's only internet gateway is the templated one.
    _assert_attached(ctx, ec2, vpc_id, first_igw)

    # ---- 2. in-place: the same attachment now joins the second gateway
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template("IgwB"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    second_igw = ids["IgwB"]
    assert set(ids) == {"Vpc", "IgwB", "Attachment"}, f"stack resources after the swap {ids!r}"
    assert ids["Attachment"] == attachment, "an in-place update keeps the attachment"
    _assert_in_place(
        _rows(_events(cfn, ref["stack"]), seen, "Attachment"), attachment, "Attachment"
    )
    _assert_attached(ctx, ec2, vpc_id, second_igw)
    _assert_gone(ctx, lambda: _describe_igw(ec2, first_igw), _IGW_NOT_FOUND, first_igw)

    # ---- 3. delete: the stack detaches and deletes the gateway, then deletes the VPC
    _delete_stack(ctx, cfn, ref["stack"])
    _assert_gone(ctx, lambda: _describe_igw(ec2, second_igw), _IGW_NOT_FOUND, second_igw)
    _assert_gone(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), _VPC_NOT_FOUND, vpc_id)


def _describe_igw(ec2, igw_id: str) -> dict:
    return ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][0]


def _assert_attached(ctx, ec2, vpc_id: str, igw_id: str) -> None:
    """*igw_id* reports one available attachment to *vpc_id*, and the VPC no other gateway."""

    def read() -> dict:
        attached = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]
        return {
            "gateway": _describe_igw(ec2, igw_id).get("Attachments"),
            "vpc": sorted(g["InternetGatewayId"] for g in attached),
        }

    want = {"gateway": [{"State": "available", "VpcId": vpc_id}], "vpc": [igw_id]}
    _wait_for(ctx, read, want, f"attachment of {igw_id} to {vpc_id}")


def _assert_gone(ctx, read, pair: tuple[str, str], resource_id: str) -> None:
    got = _wait_error(ctx, read, pair[0], resource_id)
    assert got == (pair[0], pair[1].format(resource_id)), (
        f"reading {resource_id} after its delete answered {got!r}"
    )


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


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


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
