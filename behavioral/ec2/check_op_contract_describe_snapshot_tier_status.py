"""op-contract-describeSnapshotTierStatus."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSnapshotTierStatus"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."
_TERMINAL_TIERING_STATUSES = {
    "archival-completed",
    "archival-failed",
    "temporary-restore-completed",
    "temporary-restore-failed",
    "permanent-restore-completed",
    "permanent-restore-failed",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSnapshotTierStatus surfaces a snapshot once it has been registered with the
    tiering-status tracker (via ModifySnapshotTier), reports it on the archive storage tier once
    the archival transition reaches its terminal archival-completed status, and honors DryRun."""
    ec2 = ctx.client("ec2")
    volume_id, snapshot_id = _create_volume_and_snapshot(ctx, ec2)

    # A snapshot only gets a defined storage tier once it has actually finished being created --
    # while it is still "pending", DescribeSnapshotTierStatus legitimately has nothing to report
    # for it yet, and polling *that* API alone (without first waiting for the snapshot itself to
    # complete) can spin for the entire budget with zero results. Wait for the snapshot to reach
    # "completed" first, which for a freshly created, empty 1 GiB volume happens well within the
    # harness's per-check wall-clock budget (~900s).
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=180,
        interval_s=10,
    )

    # A plain, never-tiered snapshot on real AWS simply has NO entry in
    # DescribeSnapshotTierStatus's inventory -- that inventory tracks snapshots that have gone
    # through a tiering operation, not every snapshot the account owns. Polling forever for a
    # merely-completed snapshot to "show up" spins on an empty list no matter how long you wait
    # (that's what a naive poll here actually observes against real AWS). ModifySnapshotTier is
    # what registers the snapshot with the tiering-status tracker. StorageTier reads "standard"
    # while LastTieringOperationStatus is archival-in-progress; both are transient, so the check
    # polls to a terminal tiering status and grades that. Archiving an empty 1 GiB snapshot
    # reaches archival-completed in about a minute on real AWS.
    ec2.modify_snapshot_tier(SnapshotId=snapshot_id, StorageTier="archive")

    def _fetch():
        # Page through the full, unfiltered result set and match client-side rather than
        # server-side filtering by "snapshot-id" -- avoids depending on filter-index freshness
        # and is still a bounded amount of work since a fresh test account has few snapshots.
        items = []
        token = None
        while True:
            kwargs = {"MaxResults": 500}
            if token:
                kwargs["NextToken"] = token
            resp = ec2.describe_snapshot_tier_status(**kwargs)
            _, page_items = _sole_list_field(resp)
            items.extend(page_items)
            token = resp.get("NextToken")
            if not token:
                break
        return [i for i in items if i.get("SnapshotId") == snapshot_id]

    items = _poll_until(
        _fetch,
        lambda items: len(items) == 1
        and items[0].get("LastTieringOperationStatus") in _TERMINAL_TIERING_STATUSES,
        timeout_s=420,
        interval_s=10,
    )
    item = items[0]
    assert item["SnapshotId"] == snapshot_id, f"expected {snapshot_id}, got {item['SnapshotId']!r}"
    assert item["VolumeId"] == volume_id, f"expected {volume_id}, got {item['VolumeId']!r}"
    assert item["LastTieringOperationStatus"] == "archival-completed", (
        f"unexpected terminal tiering status: {item['LastTieringOperationStatus']!r}"
    )
    assert item["StorageTier"] == "archive", f"unexpected storage tier: {item['StorageTier']!r}"
    assert item["LastTieringProgress"] == 100, f"unexpected tiering progress: {item['LastTieringProgress']!r}"

    code, message = _error(lambda: ec2.describe_snapshot_tier_status(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _sole_list_field(resp):
    skip = {"ResponseMetadata", "NextToken", "RequestId"}
    for k, v in resp.items():
        if k in skip:
            continue
        if isinstance(v, list):
            return k, v
    raise AssertionError(f"no list field found in response: {sorted(resp.keys())}")


def _create_volume_and_snapshot(ctx, ec2):
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-snaptier-")
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VolumeId"]

    def _cleanup_volume():
        try:
            ec2.delete_volume(VolumeId=volume_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                raise

    ctx.on_cleanup(_cleanup_volume)

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
    )

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"{name} snapshot",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": name}]}],
    )["SnapshotId"]

    def _cleanup_snapshot():
        try:
            _poll_until(
                lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
                lambda s: s == "completed",
                timeout_s=180,
            )
        except AssertionError:
            pass
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise

    ctx.on_cleanup(_cleanup_snapshot)
    return volume_id, snapshot_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
