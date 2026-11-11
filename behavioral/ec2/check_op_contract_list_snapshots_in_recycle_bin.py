"""op-contract-list-snapshots-in-recycle-bin."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-list-snapshots-in-recycle-bin"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted, tag-matched snapshot lands in ListSnapshotsInRecycleBin and can be restored."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")
    tag_key = "sim2real-rbin-marker"
    tag_value = ctx.unique_name("snap-")
    az = _first_available_az(ctx)

    rule = rbin.create_rule(
        Description="sim2real behavioral check retention rule (snapshots)",
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
    )
    rule_id = rule["Identifier"]
    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3")["VolumeId"]
    ctx.on_cleanup(lambda: _final_cleanup(ec2, rbin, rule_id, volume_id, [None]))

    # A freshly created Recycle Bin rule starts out "pending" and only applies to resources
    # deleted once it becomes "available" — deleting before then bypasses the bin entirely (the
    # snapshot is purged for good, so it never shows up in ListSnapshotsInRecycleBin).
    _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=3.0,
    )

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    # --- error boundary: DryRun must reject before listing anything ---
    code, message = _error(lambda: ec2.list_snapshots_in_recycle_bin(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message {message!r}"

    # deleting a tag-matched snapshot sends it to the Recycle Bin instead of purging it; GetRule
    # reports "available" before the rule is enforced, so fresh snapshots are deleted until one lands.
    snapshot_id, entry = _delete_into_bin(ctx, ec2, rbin, rule_id, volume_id, [{"Key": tag_key, "Value": tag_value}])
    assert entry["SnapshotId"] == snapshot_id, (
        f"expected bin entry for {snapshot_id!r}, got {entry.get('SnapshotId')!r}"
    )
    assert "RecycleBinEnterTime" in entry, f"expected RecycleBinEnterTime in entry, got keys {sorted(entry)}"
    assert "RecycleBinExitTime" in entry, f"expected RecycleBinExitTime in entry, got keys {sorted(entry)}"
    assert entry["Description"] == "sim2real-rbin-snapshot-contract", (
        f"expected description 'sim2real-rbin-snapshot-contract', got {entry.get('Description')!r}"
    )

    # restore it back to active use
    ec2.restore_snapshot_from_recycle_bin(SnapshotId=snapshot_id)
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=60.0,
    )
    assert _find_snapshot_in_bin(ec2, snapshot_id) is None, (
        "snapshot still listed in Recycle Bin after restore"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _first_available_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError("no available Availability Zones found")
    return azs[0]["ZoneName"]


def _delete_into_bin(ctx, ec2, rbin, rule_id, volume_id, tags, timeout_s=600.0):
    """Delete fresh tagged snapshots until one shows up in ListSnapshotsInRecycleBin (a snapshot
    deleted before the rule is enforced is purged); return (snapshot_id, entry). Each is cleaned up."""
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    attempts: list = []

    def _binned():
        for sid in attempts:
            entry = _find_snapshot_in_bin(ec2, sid)
            if entry is not None:
                return sid, entry
        return None

    while True:
        attempt_id = ec2.create_snapshot(
            VolumeId=volume_id,
            Description="sim2real-rbin-snapshot-contract",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": tags}],
        )["SnapshotId"]
        attempts.append(attempt_id)
        ctx.on_cleanup(lambda c=attempt_id: _final_cleanup(ec2, rbin, rule_id, volume_id, [c]))
        _poll_until(
            lambda: ec2.describe_snapshots(SnapshotIds=[attempt_id])["Snapshots"][0]["State"],
            lambda s: s == "completed",
            timeout_s=180.0,
            interval_s=2.0,
        )
        ec2.delete_snapshot(SnapshotId=attempt_id)
        try:
            return _poll_until(_binned, lambda found: found is not None, timeout_s=60.0, interval_s=2.0)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"rule {rule_id} sent none of the deleted snapshots {attempts} to the Recycle Bin within {timeout_s:.0f}s"
                ) from None


def _find_snapshot_in_bin(ec2, snapshot_id: str):
    from botocore.exceptions import ClientError

    try:
        resp = ec2.list_snapshots_in_recycle_bin(SnapshotIds=[snapshot_id])
    except ClientError as e:
        # Right after deletion the snapshot may not have landed in the bin yet; AWS rejects a
        # SnapshotIds filter for an id it doesn't (yet) recognize as bin-resident instead of
        # returning an empty list — treat that the same as "not there yet".
        if e.response["Error"]["Code"] in {
            "InvalidSnapshot.NotFound",
            "SnapshotNotInRecycleBin",
        }:
            return None
        raise
    # The API's response member for this operation is "Snapshots" (not the shape name
    # "SnapshotRecycleBinInfo" used for each list item).
    items = resp.get("Snapshots", [])
    return items[0] if items else None


def _final_cleanup(ec2, rbin, rule_id, volume_id, snapshot_id_holder) -> None:
    try:
        rbin.delete_rule(Identifier=rule_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    snapshot_id = snapshot_id_holder[0]
    if snapshot_id:
        try:
            ec2.restore_snapshot_from_recycle_bin(SnapshotId=snapshot_id)
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "InvalidSnapshot.NotFound"
                and not (err["Code"] == "InvalidState" and "The snapshot is not recoverable" in err.get("Message", ""))
            ):
                raise
        _delete_or_gone(
            lambda: ec2.delete_snapshot(SnapshotId=snapshot_id),
            ("InvalidSnapshot.NotFound",),
            ("InvalidSnapshot.InUse", "IncorrectState"),
        )
    _delete_or_gone(
        lambda: ec2.delete_volume(VolumeId=volume_id),
        ("InvalidVolume.NotFound",),
        ("VolumeInUse", "IncorrectState"),
    )


def _delete_or_gone(fn, gone, busy, timeout_s=60.0):
    """Teardown delete: done on a not-found code in gone; a code in busy (still releasing) is
    retried every 2 s up to timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
