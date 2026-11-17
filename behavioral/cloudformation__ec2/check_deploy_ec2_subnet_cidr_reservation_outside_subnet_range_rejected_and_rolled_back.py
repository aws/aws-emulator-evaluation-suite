"""deploy-ec2-subnet-cidr-reservation-outside-subnet-range-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-subnet-cidr-reservation-outside-subnet-range-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_GOOD_CIDR = "10.96.1.128/28"
_BAD_CIDR = "10.200.0.0/28"

#: EC2's refusal of a VPC that no longer exists.
_VPC_NOT_FOUND = ("InvalidVpcID.NotFound", "The vpc ID '{}' does not exist")

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _template(cidr: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR},
                },
                "Reservation": {
                    "Type": "AWS::EC2::SubnetCidrReservation",
                    "Properties": {
                        "SubnetId": {"Ref": "Subnet"},
                        "Cidr": cidr,
                        "ReservationType": "explicit",
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation subnet CIDR reservation outside its subnet's own range fails to create
    and rolls the whole stack back, leaving no VPC, subnet or reservation behind.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    good_name = ctx.unique_name("sim2real-cfnscrbad-good-")
    bad_name = ctx.unique_name("sim2real-cfnscrbad-bad-")
    good_ref = {"stack": good_name}
    bad_ref = {"stack": bad_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_ref))
    ctx.on_cleanup(lambda: _teardown_stack(cfn, good_ref))

    # Positive control: the same shape of template with a CIDR inside the subnet deploys cleanly.
    good_ref["stack"], good_stack = _create_stack_past_vpc_contention(
        ctx, cfn, good_name, _template(_GOOD_CIDR)
    )
    _expect(cfn, good_stack, "CREATE_COMPLETE")
    good_ids = _physical_ids(cfn, good_ref["stack"])
    good_subnet = good_ids["Subnet"]
    reservations = ec2.get_subnet_cidr_reservations(SubnetId=good_subnet)["SubnetIpv4CidrReservations"]
    assert [r["Cidr"] for r in reservations] == [_GOOD_CIDR], f"reservations on {good_subnet}: {reservations!r}"

    # The control stack is torn down before the negative's stack exists, so the two never hold
    # a VPC each at the same time.
    _delete_stack(ctx, cfn, good_ref["stack"])

    # The negative: a CIDR the subnet does not contain fails CreateSubnetCidrReservation, and
    # the whole stack (VPC and subnet included) rolls back rather than leaving a partial stack.
    bad_ref["stack"], bad_stack = _create_stack_past_vpc_contention(
        ctx, cfn, bad_name, _template(_BAD_CIDR)
    )
    assert bad_stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {bad_stack['StackStatus']!r}"
    )
    # DescribeStackEvents can briefly lag the terminal stack status it is read right after.
    events = _wait_for_failed_reason(ctx, cfn, bad_ref["stack"], "Reservation")
    reason = _failed_reason(events, "Reservation")
    message, code = _handler_reason(reason)
    masked_message = re.sub(r"Request ID: [0-9a-f-]+\)$", "Request ID: <id>)", message)
    expected_message = (
        f"Reservation CIDR should within subnet CIDR block {_SUBNET_CIDR} (Service: EC2; "
        "Operation: CreateSubnetCidrReservation; Status Code: 400; Error Code: "
        "InvalidParameterValue; Request ID: <id>)"
    )
    assert (code, masked_message) == ("InvalidRequest", expected_message), (
        f"expected (InvalidRequest, {expected_message!r}), got ({code!r}, {message!r})"
    )

    # Nothing from the rolled-back stack remains: the VPC it created is gone.
    vpc_rows = [
        e.get("PhysicalResourceId")
        for e in events
        if e["LogicalResourceId"] == "Vpc" and e["ResourceStatus"] == "DELETE_COMPLETE"
    ]
    assert len(vpc_rows) == 1, f"expected exactly one VPC DELETE_COMPLETE row, got {vpc_rows!r}"
    got = _wait_error(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_rows[0]]), _VPC_NOT_FOUND[0], vpc_rows[0])
    assert got == (_VPC_NOT_FOUND[0], _VPC_NOT_FOUND[1].format(vpc_rows[0])), (
        f"DescribeVpcs after the rollback answered {got!r}"
    )


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


def _wait_for_failed_reason(ctx, cfn, stack_id: str, logical_id: str) -> list[dict]:
    """Poll DescribeStackEvents until *logical_id* shows a CREATE_FAILED row; return all events."""
    timeout = _budget_s(ctx, 30.0)
    deadline = time.monotonic() + timeout
    while True:
        events = _events(cfn, stack_id)
        if any(
            e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
            for e in events
        ):
            return events
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended waiting for {logical_id}'s CREATE_FAILED event")
            summary = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]
            raise AssertionError(f"{logical_id} never shows CREATE_FAILED after {timeout:.0f}s: {summary!r}")
        time.sleep(_POLL_S)


def _failed_reason(events: list[dict], logical_id: str) -> str:
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(rows) == 1, f"expected exactly one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _handler_reason(reason: str) -> tuple[str, str]:
    """``(message, HandlerErrorCode)`` of a registry-handler CREATE_FAILED reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return m["message"], m["code"]


# ===== helpers =====


def _budget_s(ctx, cap_s):
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
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
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
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
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _wait_error(ctx, fn, code: str, what: str):
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
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] in ("DELETE_COMPLETE", "ROLLBACK_COMPLETE"):
        if stack["StackStatus"] == "ROLLBACK_COMPLETE":
            _delete_stack(None, cfn, stack["StackId"])
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
        if stack["StackStatus"] == "ROLLBACK_COMPLETE":
            _delete_stack(None, cfn, stack["StackId"])
            return
    _delete_stack(None, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
