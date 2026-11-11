"""op-contract-restore-snapshot-from-recycle-bin."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-restore-snapshot-from-recycle-bin"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A snapshot deleted while a matching Recycle Bin retention rule is active lands in the
    bin (not visible via DescribeSnapshots) and RestoreSnapshotFromRecycleBin brings it back
    to active use; a syntactically malformed id is rejected with InvalidSnapshotID.Malformed."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")

    # Error boundary first (doesn't need any recycle-bin infrastructure): restoring a
    # snapshot id that simply does not exist at all. The "...1234567890abcdef0" long-format
    # id is the placeholder AWS's own docs/SDK examples use for a syntactically valid
    # resource id, but on real AWS it does not clear RestoreSnapshotFromRecycleBin's own
    # id-format validator (distinct from, and stricter than, the existence check): the
    # service rejects it with InvalidSnapshotID.Malformed before ever reaching the NotFound
    # existence boundary.
    err = _error(
        lambda: ec2.restore_snapshot_from_recycle_bin(SnapshotId="snap-1234567890abcdef0")
    )
    assert err["Code"] == "InvalidSnapshotID.Malformed", f"unexpected error code for unknown id: {err!r}"
    assert err.get("Message") == "The snapshot ID 'snap-1234567890abcdef0' is malformed", (
        f"unexpected message: {err.get('Message')!r}"
    )

    tag_key = "sim2real-rbin"
    tag_value = ctx.unique_name("snap-")

    rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    if not _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda status: status == "available",
        timeout_s=120,
        interval_s=5,
    ):
        raise AssertionError(
            "unreachable: Recycle Bin retention rule never became available",
        )

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    volume_id = ec2.create_volume(Size=1, AvailabilityZone=az, VolumeType="gp3")["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # A rule that reads "available" can still lag before it retains deletions, and a
    # snapshot deleted inside that lag is gone for good rather than binned. So the
    # create/delete pair is retried with a fresh snapshot (bounded) until one lands in
    # the bin; every attempt's snapshot stays registered for cleanup.
    def _make_snapshot() -> str:
        sid = ec2.create_snapshot(
            VolumeId=volume_id,
            TagSpecifications=[
                {"ResourceType": "snapshot", "Tags": [{"Key": tag_key, "Value": tag_value}]}
            ],
        )["SnapshotId"]
        ctx.on_cleanup(lambda: _delete_snapshot_quiet(ec2, sid))
        ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[sid], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        return sid

    attempts: list[str] = []
    snap_id = None
    deadline = time.monotonic() + 480
    while snap_id is None and time.monotonic() < deadline:
        attempts.append(_make_snapshot())
        ec2.delete_snapshot(SnapshotId=attempts[-1])
        snap_id = _poll_until(
            lambda: _first_binned(ec2.list_snapshots_in_recycle_bin, "Snapshots", "SnapshotId", attempts),
            lambda found: bool(found),
            timeout_s=90,
            interval_s=5,
        ) or None
    if snap_id is None:
        raise AssertionError(
            f"unreachable: none of the deleted snapshots {attempts} appeared in Recycle Bin "
            "within the test window",
        )

    # A recycle-binned snapshot is absent from the normal read path: DescribeSnapshots fails with
    # InvalidSnapshot.NotFound rather than returning an empty list.
    err = _error(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id]))
    assert err["Code"] == "InvalidSnapshot.NotFound", (
        f"expected recycle-binned snapshot to read as not-found, got: {err!r}"
    )
    assert err.get("Message") == f"The snapshot '{snap_id}' does not exist.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    ec2.restore_snapshot_from_recycle_bin(SnapshotId=snap_id)

    def _restored() -> bool:
        try:
            resp = ec2.describe_snapshots(SnapshotIds=[snap_id])
        except Exception:
            return False
        snaps = resp.get("Snapshots", [])
        return bool(snaps) and snaps[0]["State"] == "completed"

    assert _poll_until(_restored, lambda ok: ok, timeout_s=60, interval_s=5), (
        "snapshot was not visible/active again after RestoreSnapshotFromRecycleBin"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


def _first_binned(list_fn, items_key, id_key, wanted):
    """Return the first id from ``wanted`` that the recycle bin lists, or None. The bin is
    listed unfiltered, so an id that was never binned cannot fail the whole read."""
    kwargs: dict = {}
    while True:
        page = list_fn(**kwargs)
        for entry in page.get(items_key, []):
            if entry[id_key] in wanted:
                return entry[id_key]
        if not page.get("NextToken"):
            return None
        kwargs["NextToken"] = page["NextToken"]


def _delete_snapshot_quiet(ec2, snap_id):
    """Cleanup: delete the snapshot, tolerating one already deleted (or binned) by the check."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_snapshot(SnapshotId=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
