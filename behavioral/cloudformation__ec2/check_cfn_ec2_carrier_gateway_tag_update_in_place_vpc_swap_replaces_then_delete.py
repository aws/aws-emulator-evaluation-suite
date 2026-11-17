"""cfn-ec2-carrier-gateway-tag-update-in-place-vpc-swap-replaces-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-carrier-gateway-tag-update-in-place-vpc-swap-replaces-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_A_CIDR = "10.94.0.0/16"
_VPC_B_CIDR = "10.95.0.0/16"

#: EC2's refusal of a carrier gateway, and a VPC, that no longer exist.
_NOT_FOUND = ("InvalidCarrierGatewayID.NotFound", "The CarrierGateway ID '{}' does not exist")
_VPC_NOT_FOUND = ("InvalidVpcID.NotFound", "The vpc ID '{}' does not exist")


def _template(vpc_logical: str, vpc_cidr: str, name: str) -> str:
    # The stack holds exactly one VPC at a time: moving the gateway swaps VpcA's logical
    # resource for VpcB's rather than adding a second VPC alongside it.
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                vpc_logical: {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": vpc_cidr, "Tags": _TAGS}},
                "Gateway": {
                    "Type": "AWS::EC2::CarrierGateway",
                    "Properties": {
                        "VpcId": {"Ref": vpc_logical},
                        "Tags": _TAGS + [{"Key": "Name", "Value": name}],
                    },
                },
            },
            "Outputs": {"GatewayId": {"Value": {"Fn::GetAtt": ["Gateway", "CarrierGatewayId"]}}},
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation carrier gateway attaches to exactly the VPC its template names.

    A Name tag change updates the same gateway in place; moving it to a second VPC replaces it
    with a new gateway id; delete removes the gateway entirely.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-carriergateway.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfncgw-")
    first = ctx.unique_name("sim2real-cfncgw-a-")
    second = ctx.unique_name("sim2real-cfncgw-b-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: the gateway attaches to the templated VPC
    ref["stack"], stack = _create_stack_past_vpc_contention(
        ctx, cfn, stack_name, _template("VpcA", _VPC_A_CIDR, first), Tags=_TAGS
    )
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_a, gateway_id = ids["VpcA"], ids["Gateway"]
    assert _outputs(stack) == {"GatewayId": gateway_id}, f"GetAtt outputs {_outputs(stack)!r}"
    stamped = _stack_tags(stack_name, ref["stack"], "Gateway")
    _assert_gateway(ctx, ec2, gateway_id, vpc_a, {"Name": first, **stamped})

    # ---- 2. in-place: a new Name tag, the same gateway
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template("VpcA", _VPC_A_CIDR, second), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Gateway"] == gateway_id, "a Tags-only update keeps the gateway"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Gateway"), gateway_id, "Gateway")
    _assert_gateway(ctx, ec2, gateway_id, vpc_a, {"Name": second, **stamped})

    # ---- 3. replacement: VpcId is create-only, and naming a different VPC logical id swaps
    #         the stack onto a second VPC, replacing the gateway with a new gateway id
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template("VpcB", _VPC_B_CIDR, second), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    vpc_b, new_gateway_id = ids["VpcB"], ids["Gateway"]
    assert set(ids) == {"VpcB", "Gateway"}, f"stack resources after the swap {ids!r}"
    assert new_gateway_id != gateway_id, "moving to a new VPC must replace the gateway"
    _assert_replaced(_rows(_events(cfn, ref["stack"]), seen, "Gateway"), gateway_id, new_gateway_id, "Gateway")
    _assert_gateway(ctx, ec2, new_gateway_id, vpc_b, {"Name": second, **stamped})
    _assert_gone(ctx, ec2, gateway_id)
    got = _wait_error(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_a]), _VPC_NOT_FOUND[0], vpc_a)
    assert got == (_VPC_NOT_FOUND[0], _VPC_NOT_FOUND[1].format(vpc_a)), (
        f"DescribeVpcs for the dropped VpcA answered {got!r}"
    )

    # ---- 4. delete: the gateway is gone too
    _delete_stack(ctx, cfn, ref["stack"])
    _assert_gone(ctx, ec2, new_gateway_id)


def _assert_gateway(ctx, ec2, gateway_id: str, vpc_id: str, extra_tags: dict) -> None:
    def read() -> dict:
        gw = ec2.describe_carrier_gateways(CarrierGatewayIds=[gateway_id])["CarrierGateways"][0]
        return {"VpcId": gw.get("VpcId"), "State": gw.get("State"), "Tags": _tag_map(gw.get("Tags"))}

    def done(got: dict) -> bool:
        return (
            got["VpcId"] == vpc_id
            and got["State"] in ("available", "pending")
            and got["Tags"] == {"sim2real": CHECK, **extra_tags}
        )

    got = _wait_until(ctx, read, done, f"DescribeCarrierGateways {gateway_id}")
    assert got["State"] in ("available", "pending"), f"unexpected carrier gateway state {got!r}"


def _assert_gone(ctx, ec2, gateway_id: str) -> None:
    got = _wait_error(
        ctx,
        lambda: ec2.describe_carrier_gateways(CarrierGatewayIds=[gateway_id]),
        _NOT_FOUND[0],
        gateway_id,
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(gateway_id)), (
        f"DescribeCarrierGateways for {gateway_id} answered {got!r}"
    )


# ===== helpers =====


def _tag_map(tags_in: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags_in or []}


def _stack_tags(stack_name: str, stack_id: str, logical_id: str) -> dict[str, str]:
    """The tags CloudFormation itself stamps on an EC2 resource it creates."""
    return {
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": logical_id,
    }


def _wait_until(ctx, read, done, what: str):
    """Poll ``read()`` until ``done(result)``: EC2 reads are eventually consistent."""
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = read()
        if done(got):
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with {what} at {got!r}")
            raise AssertionError(f"{what} never reached the expected state, last read {got!r}")
        time.sleep(_POLL_S)


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
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced(rows: list[tuple], old_physical_id: str, new_physical_id: str, logical_id: str) -> None:
    """The replacement settles on *new_physical_id* and deletes *old_physical_id*.

    CFN logs a replacement's new resource under the logical id's own UPDATE_* events (create
    then delete, or delete then create, by the resource type's replacement strategy), never
    under CREATE_COMPLETE.
    """
    old_events = [(status, pid) for status, _, pid in rows if pid == old_physical_id]
    new_events = [(status, pid) for status, _, pid in rows if pid == new_physical_id]
    assert ("UPDATE_COMPLETE", new_physical_id) in new_events, (
        f"{logical_id}'s new resource {new_physical_id!r} never settled: {rows!r}"
    )
    assert ("DELETE_COMPLETE", old_physical_id) in old_events, (
        f"{logical_id}'s old resource {old_physical_id!r} was never deleted: {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
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
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
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
