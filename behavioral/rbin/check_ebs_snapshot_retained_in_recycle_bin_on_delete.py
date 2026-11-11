"""ebs-snapshot-retained-in-recycle-bin-on-delete."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "ebs-snapshot-retained-in-recycle-bin-on-delete"
GROUP = "e2e"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag-level rbin rule retains a matching, deleted EBS snapshot in the Recycle Bin
    instead of letting it be permanently deleted, and the snapshot can be restored."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    tag_key = "sim2real-rbin-test"
    tag_value = ctx.unique_name("snap-")

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rbin-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_safe(ctx, vol_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[vol_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
        Description=ctx.unique_name("sim2real-rbin-rule-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: _delete_rule_safe(ctx, rule_id))

    _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda status: status == "available",
        timeout_s=60,
    )

    # A rule reports "available" up to several minutes before it is enforced: delete fresh
    # matching snapshots until the rule retains one, which becomes the subject below.
    snap_id, retained = _delete_until_retained(
        ctx, ec2, vol_id, [{"Key": tag_key, "Value": tag_value}], timeout_s=700.0
    )
    assert retained[0]["SnapshotId"] == snap_id
    assert "RecycleBinEnterTime" in retained[0], f"missing RecycleBinEnterTime: {retained[0]!r}"

    # It must no longer be visible as a normal, live snapshot.
    code, message = _error(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id]))
    assert code == "InvalidSnapshot.NotFound", code
    assert message == f"The snapshot '{snap_id}' does not exist.", message

    # Restore it from the Recycle Bin and confirm it becomes a normal snapshot again.
    ec2.restore_snapshot_from_recycle_bin(SnapshotId=snap_id)
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda state: state == "completed",
        timeout_s=120,
    )

    # Remove the rule now so the final teardown's delete_snapshot call permanently
    # deletes the snapshot instead of being retained again.
    _delete_rule_safe(ctx, rule_id)


# ===== helpers =====
def _delete_until_retained(ctx, ec2, vol_id: str, snap_tags: list[dict], *, timeout_s: float) -> tuple[str, list[dict]]:
    """Each pass deletes a new matching snapshot and polls the Recycle Bin for every one deleted so
    far; returns the first retained id and its listing. One deleted before enforcement is gone."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 30.0)))
    tried: list[str] = []
    while True:
        snap_id = ec2.create_snapshot(
            VolumeId=vol_id, TagSpecifications=[{"ResourceType": "snapshot", "Tags": snap_tags}]
        )["SnapshotId"]
        ctx.on_cleanup(lambda sid=snap_id: _delete_snapshot_safe(ctx, sid))
        ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ec2.delete_snapshot(SnapshotId=snap_id)
        tried.append(snap_id)
        pass_end = min(deadline, time.monotonic() + 60.0)
        while True:
            for sid in tried:
                snaps = _list_in_recycle_bin(ec2, sid)
                if len(snaps) == 1:
                    return sid, snaps
            if time.monotonic() >= pass_end:
                break
            time.sleep(2)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no deleted snapshot matching the rule's tag was retained in the Recycle Bin "
                f"within {timeout_s}s; deleted: {tried}"
            )


def _list_in_recycle_bin(ec2, snap_id: str) -> list[dict]:
    from botocore.exceptions import ClientError

    try:
        return ec2.list_snapshots_in_recycle_bin(SnapshotIds=[snap_id]).get("Snapshots", [])
    except ClientError as err:
        # Immediately after delete_snapshot, before the deletion has propagated into the
        # Recycle Bin backend, real AWS rejects a SnapshotIds filter for the not-yet-resident
        # id instead of returning an empty list — treat that the same as "not there yet".
        if err.response["Error"]["Code"] in ("InvalidSnapshot.NotFound", "SnapshotNotInRecycleBin"):
            return []
        raise


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _delete_rule_safe(ctx, rule_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("rbin").delete_rule(Identifier=rule_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_snapshot_safe(ctx, snap_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("ec2").delete_snapshot(SnapshotId=snap_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidSnapshot.NotFound",):
            raise


def _delete_volume_safe(ctx, vol_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("ec2").delete_volume(VolumeId=vol_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVolume.NotFound",):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
