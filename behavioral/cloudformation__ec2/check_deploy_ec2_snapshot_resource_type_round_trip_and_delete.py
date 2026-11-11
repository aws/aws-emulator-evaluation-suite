"""deploy-ec2-snapshot-resource-type-round-trip-and-delete."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-snapshot-resource-type-round-trip-and-delete"
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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


_VOLUME_SIZE_GIB = 1

def _template(az: str, description: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vol": {
                "Type": "AWS::EC2::Volume",
                "Properties": {
                    "AvailabilityZone": az, "Size": _VOLUME_SIZE_GIB, "VolumeType": "gp3",
                },
            },
            "Snap": {
                "Type": "AWS::EC2::Snapshot",
                "Properties": {
                    "VolumeId": {"Ref": "Vol"},
                    "Description": description,
                },
            },
        },
        "Outputs": {
            "VolId": {"Value": {"Ref": "Vol"}},
            "SnapArn": {"Value": {"Ref": "Snap"}},
            "SnapId": {"Value": {"Fn::GetAtt": ["Snap", "SnapshotId"]}},
        },
    })


def _poll_snapshot_completed(ec2, snap_id: str, *, timeout_s: float = 600.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    snap = None
    while True:
        snap = ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]
        if snap["State"] == "completed":
            return snap
        assert snap["State"] != "error", f"snapshot {snap_id} entered state 'error'"
        if time.monotonic() >= deadline:
            raise AssertionError(f"snapshot {snap_id} still {snap['State']!r} after {timeout_s}s")
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::Snapshot resource (declared directly, not via DeletionPolicy)
    is a real EBS snapshot of its VolumeId, whose Ref is the snapshot ARN, and DeleteStack
    removes both the snapshot and its source volume from the EC2 API.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert zones, f"no available availability zone in {ctx.region!r}"
    az = zones[0]

    name = ctx.unique_name("sim2real-xsvc-snap-")
    stack_id = create_stack(ctx, cfn, name, _template(az, name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"snapshot stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    vol_id, snap_arn, snap_id = out["VolId"], out["SnapArn"], out["SnapId"]

    # 1. the volume (prerequisite) really exists.
    vol = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
    got = (vol["State"], vol["Size"], vol["AvailabilityZone"], vol["VolumeType"])
    assert got == ("available", _VOLUME_SIZE_GIB, az, "gp3"), (
        f"volume {vol_id} is {got!r}, expected ('available', {_VOLUME_SIZE_GIB}, {az!r}, 'gp3')"
    )

    # 2. the snapshot's Ref is its ARN (the type's primary identifier), built from the account,
    # region and the snapshot id GetAtt independently returns.
    partition = stack_id.split(":")[1]
    expected_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:snapshot/{snap_id}"
    assert snap_arn == expected_arn, (
        f"Ref of the Snapshot resource is {snap_arn!r}, expected the snapshot ARN {expected_arn!r}"
    )

    # 3. the snapshot is a real, completed EBS snapshot of exactly this volume, with the
    # template's Description, read back through EC2 by the GetAtt SnapshotId (not the Ref).
    snap = _poll_snapshot_completed(ec2, snap_id, timeout_s=600.0)
    owned = paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"],
                     Filters=[{"Name": "description", "Values": [name]}])
    assert [x["SnapshotId"] for x in owned] == [snap_id], (
        f"own snapshots described {name!r}: {owned!r}, GetAtt SnapshotId {snap_id!r}"
    )
    assert (snap["VolumeId"], snap["VolumeSize"], snap["Description"]) == (vol_id, _VOLUME_SIZE_GIB, name), (
        f"snapshot {snap_id} read back as "
        f"{(snap['VolumeId'], snap['VolumeSize'], snap['Description'])!r}, expected "
        f"{(vol_id, _VOLUME_SIZE_GIB, name)!r}"
    )

    # 4. DeleteStack removes the snapshot and the volume, each with its exact NotFound.
    delete_stack(cfn, stack_id)
    expect_error(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id]),
                 *("InvalidSnapshot.NotFound", f"The snapshot '{snap_id}' does not exist."))
    expect_error(lambda: ec2.describe_volumes(VolumeIds=[vol_id]),
                 *("InvalidVolume.NotFound", f"The volume '{vol_id}' does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
