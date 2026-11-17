"""cfn-ec2-vpc-dhcp-options-association-swap-replaces-then-removal-reverts-to-default."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-vpc-dhcp-options-association-swap-replaces-then-removal-reverts-to-default"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_VPC_CIDR = "10.93.0.0/16"

#: EC2's refusal of a VPC that no longer exists.
_VPC_NOT_FOUND = ("InvalidVpcID.NotFound", "The vpc ID '{}' does not exist")


def _template_vpc_only() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS}},
            },
        }
    )


def _template_with_association(dhcp_options_id: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": _TAGS}},
                "Association": {
                    "Type": "AWS::EC2::VPCDHCPOptionsAssociation",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "DhcpOptionsId": dhcp_options_id},
                },
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DHCP options association moves a VPC onto the named options set.

    Swapping either create-only property replaces it; removing it re-associates "default",
    which DescribeVpcs then reports literally, unlike a never-associated VPC's real options id.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcdhcpoptionsassociation.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnvda-")
    ref = {"stack": stack_name}

    # The options sets must be deleted only after the stack's association no longer points at
    # them, so the stack teardown is registered LAST: cleanup is LIFO, and it must run FIRST.
    opts1 = _create_dhcp_options(ctx, ec2)
    opts2 = _create_dhcp_options(ctx, ec2)
    assert opts1 != opts2, f"two created option sets collided on {opts1!r}"
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: the VPC alone starts on the account's default options set
    ref["stack"], stack = _create_stack_past_vpc_contention(
        ctx, cfn, stack_name, _template_vpc_only(), Tags=_TAGS
    )
    _expect(cfn, stack, "CREATE_COMPLETE")
    vpc_id = _physical_ids(cfn, ref["stack"])["Vpc"]
    initial_opts = _wait_dhcp_options(ctx, ec2, vpc_id, None)
    assert initial_opts not in (opts1, opts2), "a never-associated VPC's options set collided with a created one"

    # ---- 2. add the association: the VPC moves onto the first options set
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template_with_association(opts1), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    first_physical = ids["Association"]
    assert first_physical == f"{opts1}|{vpc_id}", f"association physical id {first_physical!r}"
    _wait_dhcp_options(ctx, ec2, vpc_id, opts1)

    # ---- 3. replacement: both association properties are create-only, so swapping the options
    #         set id deletes the old association (reverting to default) then creates the new one
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template_with_association(opts2), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    second_physical = _physical_ids(cfn, ref["stack"])["Association"]
    assert second_physical == f"{opts2}|{vpc_id}", f"association physical id {second_physical!r}"
    assert second_physical != first_physical, "swapping the options set id must replace the association"
    _assert_replaced(
        _rows(_events(cfn, ref["stack"]), seen, "Association"), first_physical, second_physical, "Association"
    )
    _wait_dhcp_options(ctx, ec2, vpc_id, opts2)

    # ---- 4. remove the association from the stack: its delete handler re-associates the
    #         sentinel "default", and DescribeVpcs reports that literal sentinel from then on --
    #         not the real options-set id a VPC never explicitly re-associated reports (step 1).
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template_vpc_only(), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert set(_physical_ids(cfn, ref["stack"])) == {"Vpc"}, "removing the association must leave the VPC"
    _wait_dhcp_options(ctx, ec2, vpc_id, "default")

    # ---- 5. delete the stack: the VPC itself is gone
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), _VPC_NOT_FOUND[0], vpc_id)
    assert got == (_VPC_NOT_FOUND[0], _VPC_NOT_FOUND[1].format(vpc_id)), (
        f"DescribeVpcs after the stack delete answered {got!r}"
    )


def _create_dhcp_options(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-cfnvda-opts-")
    opts = ec2.create_dhcp_options(
        DhcpConfigurations=[{"Key": "domain-name-servers", "Values": ["AmazonProvidedDNS"]}],
        TagSpecifications=[{"ResourceType": "dhcp-options", "Tags": _TAGS + [{"Key": "Name", "Value": name}]}],
    )["DhcpOptions"]
    opts_id = opts["DhcpOptionsId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_dhcp_options(DhcpOptionsId=opts_id), "InvalidDhcpOptionsID.NotFound"))
    return opts_id


def _wait_dhcp_options(ctx, ec2, vpc_id: str, want: str | None) -> str:
    """Poll DescribeVpcs until its DhcpOptionsId equals *want* (or, if None, just return it)."""
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["DhcpOptionsId"]
        if want is None or got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with DhcpOptionsId {got!r}, expected {want!r}")
            raise AssertionError(f"DhcpOptionsId of {vpc_id}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


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
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _wait_error(ctx, fn, code: str, what: str):
    timeout = _budget_s(ctx, 120.0)
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
