"""deploy-ec2-1-overlapping-subnet-cidr-rejected-and-rolled-back."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-1-overlapping-subnet-cidr-rejected-and-rolled-back"

GROUP = "deploy-cfn-ec2-network"

SERVICES = ["cloudformation", "ec2"]

VPC_BLOCK = "10.72.0.0/16"
FIRST_BLOCK = "10.72.0.0/24"
OVERLAP_BLOCK = "10.72.0.0/25"   # wholly inside FIRST_BLOCK, and itself a legal /25 in the VPC


def _template(tag: str) -> str:
    t = [{"Key": "sim2real", "Value": tag}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK, "Tags": t}},
            "First": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": FIRST_BLOCK, "Tags": t}},
            # DependsOn makes the outcome deterministic: without it both subnets are created
            # concurrently and whichever EC2 processes second is the one refused.
            "Overlap": {"Type": "AWS::EC2::Subnet", "DependsOn": "First", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": OVERLAP_BLOCK, "Tags": t}},
        },
    })


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _wait_stack_status(cfn, stack: str, timeout_s: float = 1500.0) -> dict[str, Any]:
    """Poll until the stack leaves every *_IN_PROGRESS status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        if not last["StackStatus"].endswith("_IN_PROGRESS"):
            return last
        time.sleep(5)
    raise AssertionError(f"stack {stack!r} still in progress after {timeout_s}s: "
                         f"{(last or {}).get('StackStatus')!r}")


def _settle_code(fn, want: str, timeout_s: float = 180.0) -> tuple[str | None, str | None]:
    """Poll a describe call until it raises `want` (EC2 deletes are eventually consistent);
    return the last (code, message)."""
    deadline = time.monotonic() + timeout_s
    code = message = None
    while time.monotonic() < deadline:
        try:
            fn()
            code = "<call succeeded>"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
        if code == want:
            return code, message
        time.sleep(5)
    return code, message


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_id)
        st = _wait_stack_status(cfn, stack_id)
        if st["StackStatus"] != "DELETE_COMPLETE":
            raise RuntimeError(f"stack {stack_id} ended {st['StackStatus']}: "
                               f"{st.get('StackStatusReason')}")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} delete failed: {exc!r}") from exc


def _first(events, lid: str, status: str):
    for e in events:
        if e.get("LogicalResourceId") == lid and e.get("ResourceStatus") == status:
            return e
    return None


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A stack subnet whose CIDR overlaps a sibling subnet the same stack just created fails with the
    CIDR-conflict reason, the stack reaches ROLLBACK_COMPLETE, and the rollback deletes the completed
    subnet and VPC, which EC2 then reports as InvalidSubnetID.NotFound and InvalidVpcID.NotFound."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-xsvc-ec2ovl-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=_template(name),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_stack_status(cfn, stack_id)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a stack declaring {OVERLAP_BLOCK} beside {FIRST_BLOCK} in one VPC ended "
        f"{stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}); overlapping subnets "
        f"must be refused and the stack rolled back"
    )
    events = _stack_events(cfn, stack_id)
    trail = [(e.get("LogicalResourceId"), e.get("ResourceStatus")) for e in events]

    # positive control: a non-overlapping subnet in the same VPC is accepted, and it completed
    # before the overlapping one was attempted
    first_done = _first(events, "First", "CREATE_COMPLETE")
    assert first_done is not None, f"the first subnet never completed; events: {trail!r}"
    overlap_start = _first(events, "Overlap", "CREATE_IN_PROGRESS")
    assert overlap_start is not None and overlap_start["Timestamp"] >= first_done["Timestamp"], (
        f"the overlapping subnet was not attempted after the first completed; events: {trail!r}"
    )

    # the refusal: exactly the overlapping subnet fails, with EC2's conflict message naming it
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["Overlap"], (
        f"expected exactly the overlapping subnet to fail; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    assert f"The CIDR '{OVERLAP_BLOCK}' conflicts with another subnet" in reason, (
        f"the failure reason was {reason!r}; it must be EC2's subnet-conflict refusal naming "
        f"{OVERLAP_BLOCK!r}"
    )
    # effect-absent (a): the overlapping subnet was never created at all
    assert _first(events, "Overlap", "CREATE_COMPLETE") is None, (
        f"the overlapping subnet reported CREATE_COMPLETE as well as CREATE_FAILED: {trail!r}"
    )

    # effect-absent (b): the rollback deleted the subnet and VPC that had succeeded -- the
    # subnet before the VPC it lives in
    first_gone = _first(events, "First", "DELETE_COMPLETE")
    vpc_start = _first(events, "Vpc", "DELETE_IN_PROGRESS")
    assert first_gone is not None and vpc_start is not None, (
        f"the rollback did not delete the completed resources; events: {trail!r}"
    )
    assert vpc_start["Timestamp"] >= first_gone["Timestamp"], (
        f"the rollback began deleting the VPC at {vpc_start['Timestamp'].isoformat()} before its "
        f"subnet was gone at {first_gone['Timestamp'].isoformat()}"
    )
    subnet_id = first_done["PhysicalResourceId"]
    vpc_id = _first(events, "Vpc", "CREATE_COMPLETE")["PhysicalResourceId"]
    code, message = _settle_code(lambda: ec2.describe_subnets(SubnetIds=[subnet_id]),
                                 "InvalidSubnetID.NotFound")
    assert code == "InvalidSubnetID.NotFound", (
        f"the rolled-back subnet {subnet_id} answers {code!r}, expected 'InvalidSubnetID.NotFound'"
    )
    assert message == f"The subnet ID '{subnet_id}' does not exist", (
        f"DescribeSubnets InvalidSubnetID.NotFound message: {message!r}"
    )
    code, message = _settle_code(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), "InvalidVpcID.NotFound")
    assert code == "InvalidVpcID.NotFound", (
        f"the rolled-back VPC {vpc_id} answers {code!r}, expected 'InvalidVpcID.NotFound'"
    )
    assert message == f"The vpc ID '{vpc_id}' does not exist", (
        f"DescribeVpcs InvalidVpcID.NotFound message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
