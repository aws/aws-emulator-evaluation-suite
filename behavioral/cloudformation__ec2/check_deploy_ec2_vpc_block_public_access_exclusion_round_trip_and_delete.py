"""deploy-ec2-vpc-block-public-access-exclusion-round-trip-and-delete."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ec2-vpc-block-public-access-exclusion-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


_CIDR = "10.91.0.0/24"
_MODE = "allow-bidirectional"

def _template(cidr: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": cidr},
            },
            "Exclusion": {
                "Type": "AWS::EC2::VPCBlockPublicAccessExclusion",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "InternetGatewayExclusionMode": _MODE,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "ExclusionId": {"Value": {"Ref": "Exclusion"}},
        },
    })


def _poll_exclusion_state(ec2, exclusion_id: str, want: set[str], *, timeout_s: float = 400.0) -> dict[str, Any]:
    """Poll DescribeVpcBlockPublicAccessExclusions until ``State`` lands in ``want``."""
    deadline = time.monotonic() + timeout_s
    row = None
    while True:
        row = ec2.describe_vpc_block_public_access_exclusions(
            ExclusionIds=[exclusion_id])["VpcBlockPublicAccessExclusions"][0]
        if row["State"] in want:
            return row
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"exclusion {exclusion_id} still {row['State']!r} after {timeout_s}s, expected one of {want!r}"
            )
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPC Block Public Access exclusion is stored with its mode and VPC.

    EC2 lists it for the VPC's ARN in create-complete, and DeleteStack converges it to the
    'delete-complete' tombstone.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-xsvc-vpcbpa-")
    stack_id = create_stack(ctx, cfn, name, _template(_CIDR))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"exclusion stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    vpc_id, excl_id = out["VpcId"], out["ExclusionId"]
    partition = stack_id.split(":")[1]
    vpc_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    # 1. the exclusion's Ref is its primary identifier, points at the right VPC, and reaches a
    # create-complete state in EC2 -- not just in CloudFormation.
    row = _poll_exclusion_state(ec2, excl_id, {"create-complete"})
    assert row["ExclusionId"] == excl_id, (
        f"Ref {excl_id!r} does not match the exclusion id EC2 reports: {row['ExclusionId']!r}"
    )
    assert row["InternetGatewayExclusionMode"] == _MODE, (
        f"exclusion mode read back as {row['InternetGatewayExclusionMode']!r}, expected {_MODE!r}"
    )
    assert row["ResourceArn"] == vpc_arn, (
        f"exclusion ResourceArn {row['ResourceArn']!r}, expected the VPC's ARN {vpc_arn!r}"
    )
    # Ref against an independent read: the exclusions EC2 lists for the VPC's ARN. EC2 requires
    # ExclusionIds or MaxResults; MaxResults keeps this read independent of the Ref.
    listed, kw = [], {"Filters": [{"Name": "resource-arn", "Values": [vpc_arn]}],
                      "MaxResults": 1000}
    while True:  # the operation has no paginator; follow NextToken by hand
        page = ec2.describe_vpc_block_public_access_exclusions(**kw)
        listed += [r["ExclusionId"] for r in page.get("VpcBlockPublicAccessExclusions", [])]
        if not page.get("NextToken"):
            break
        kw["NextToken"] = page["NextToken"]
    assert listed == [excl_id], f"exclusions for {vpc_arn!r}: {listed!r}, Ref {excl_id!r}"

    # 2. DeleteStack converges the exclusion to the documented 'delete-complete' tombstone --
    # deletion here is asynchronous, so this is a real EC2-side state transition, not CFN's own
    # claim.
    delete_stack(cfn, stack_id)

    gone = _poll_exclusion_state(ec2, excl_id, {"delete-complete"})
    assert gone["State"] == "delete-complete", (
        f"exclusion {excl_id} is {gone['State']!r} after delete-stack, expected 'delete-complete'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
