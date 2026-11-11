"""deep-cloudformation-2-snapshot-volume."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-2-snapshot-volume"
GROUP = 'deploy'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cf, stack_id, *, timeout_s=900, interval_s=5):
    """Poll DescribeStacks (by stack id) until the stack reaches a terminal state."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        last = stack["StackStatus"]
        if last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {last!r} after {timeout_s}s")
        time.sleep(interval_s)


def _snapshots_of(ec2, volume_id):
    """Every snapshot this account owns whose source volume is `volume_id` (paginated)."""
    out = []
    for page in ec2.get_paginator("describe_snapshots").paginate(
        OwnerIds=["self"], Filters=[{"Name": "volume-id", "Values": [volume_id]}]
    ):
        out.extend(page["Snapshots"])
    return out


def _delete_snapshot_quietly(ec2, snapshot_id):
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidSnapshot.NotFound":
            raise RuntimeError(f"snapshot {snapshot_id} delete failed: {exc!r}") from exc


def _teardown_stack_and_snapshots(cf, ec2, stack_id, holder):
    """Delete the stack (which itself snapshots the volume), wait, then delete every snapshot of
    the volume -- so a failure path that deletes the stack late cannot strand its snapshot."""
    try:
        cf.delete_stack(StackName=stack_id)
        status = _wait_terminal(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack {stack_id} teardown ended {status!r}")
    finally:
        vol = holder.get("volume_id")
        if vol:
            for snap in _snapshots_of(ec2, vol):
                _delete_snapshot_quietly(ec2, snap["SnapshotId"])


@tags("plane:control", "concern:deploy", "axis:happy-path", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """DeleteStack on a DeletionPolicy:Snapshot volume deletes the volume and leaves an EBS
    snapshot whose VolumeId is the deleted volume."""
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    zones = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    )
    assert zones, f"no available availability zone in {ctx.region!r}"

    stack_name = ctx.unique_name("sim2real-behav-snapvol-")
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vol": {
                "Type": "AWS::EC2::Volume",
                "DeletionPolicy": "Snapshot",
                "Properties": {
                    "AvailabilityZone": zones[0],
                    "Size": 1,
                    "VolumeType": "gp3",
                    "Tags": [{"Key": "sim2real", "Value": CHECK},
                             {"Key": "Name", "Value": stack_name}],
                },
            },
        },
    })
    holder: dict = {}
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack_and_snapshots(cf, ec2, stack_id, holder))

    stack = _wait_terminal(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"volume stack did not create: {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r})"
    )
    volume_id = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Vol")[
        "StackResourceDetail"]["PhysicalResourceId"]
    holder["volume_id"] = volume_id
    assert volume_id.startswith("vol-"), f"physical id is not an EBS volume id: {volume_id!r}"

    vols = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    assert len(vols) == 1 and vols[0]["Size"] == 1, (
        f"EC2 must report the stack's 1 GiB volume before the delete; got {vols!r}"
    )
    assert _snapshots_of(ec2, volume_id) == [], (
        "no snapshot of the volume may exist before DeleteStack runs"
    )

    cf.delete_stack(StackName=stack_id)
    gone = _wait_terminal(cf, stack_id)
    assert gone["StackStatus"] == "DELETE_COMPLETE", (
        f"DeleteStack must complete; got {gone['StackStatus']!r} ({gone.get('StackStatusReason')!r})"
    )

    code = message = None
    deadline = time.monotonic() + 120
    while True:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
            code = f"<present:{state}>"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
        if code == "InvalidVolume.NotFound" or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert code == "InvalidVolume.NotFound", (
        f"the volume must be deleted with the stack; DescribeVolumes -> {code!r}"
    )
    assert message == f"The volume '{volume_id}' does not exist.", (
        f"DescribeVolumes InvalidVolume.NotFound message: {message!r}"
    )

    snaps = _snapshots_of(ec2, volume_id)
    for snap in snaps:
        sid = snap["SnapshotId"]
        ctx.on_cleanup(lambda sid=sid: _delete_snapshot_quietly(ec2, sid))
    assert len(snaps) == 1, (
        f"DeletionPolicy:Snapshot must leave exactly one snapshot of {volume_id}; got "
        f"{[(s['SnapshotId'], s['State']) for s in snaps]!r}"
    )
    snap = snaps[0]
    assert snap["VolumeId"] == volume_id, (
        f"snapshot {snap['SnapshotId']!r} has VolumeId {snap['VolumeId']!r}, expected {volume_id!r}"
    )
    assert snap["VolumeSize"] == 1, f"snapshot VolumeSize {snap['VolumeSize']!r}, expected 1"
    assert snap["State"] != "error", f"snapshot {snap['SnapshotId']!r} is in state 'error'"

    # The snapshot is a real, addressable EC2 object -- not just a listing entry.
    direct = ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"]
    assert [s["VolumeId"] for s in direct] == [volume_id], (
        f"DescribeSnapshots by id disagrees with the filtered listing: {direct!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
