"""describe-snapshots-returns-inventory."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-snapshots-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_MAD_NAME = "sim2ds5e9d3f60.sim2real.test"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unfiltered DescribeSnapshots lists a manual snapshot of an Active directory, attributed to that
    DirectoryId, once it reaches Completed, and stops listing it once it is deleted."""
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    # Manual-snapshot creation on a Microsoft AD directory routinely outlives this check's
    # own body timeout. Adopt an in-flight snapshot a prior (timed-out) invocation left
    # Creating on this directory instead of creating another one on every retry -- AWS keeps
    # making progress on it in the background between retries regardless.
    existing = [
        s for s in ds.describe_snapshots(DirectoryId=directory_id)["Snapshots"]
        if s["Status"] != "Failed"
    ]
    if existing:
        snapshot_id = existing[0]["SnapshotId"]
    else:
        snapshot_id = _retry_directory_busy(
            lambda: ds.create_snapshot(DirectoryId=directory_id)["SnapshotId"]
        )
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_snapshot(SnapshotId=snapshot_id)))

    snap = _wait_for_inventory_status(ds, snapshot_id, {"Completed"}, {"Failed"}, timeout_s=260.0)
    assert snap["DirectoryId"] == directory_id, snap
    assert snap["Status"] == "Completed", snap

    _delete_snapshot_with_retry(ds, snapshot_id, timeout_s=200.0, interval_s=10.0)
    _wait_absent_from_inventory(ds, snapshot_id)


def _wait_for_inventory_status(ds, snapshot_id, terminal_ok, terminal_bad, timeout_s=220.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = ds.describe_snapshots()
        assert isinstance(resp["Snapshots"], list), resp["Snapshots"]
        match = next((s for s in resp["Snapshots"] if s["SnapshotId"] == snapshot_id), None)
        if match is not None:
            last_status = match["Status"]
            if last_status in terminal_ok:
                return match
            if last_status in terminal_bad:
                raise AssertionError(
                    f"snapshot {snapshot_id} reached {last_status} in the unfiltered inventory"
                )
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} never reached {terminal_ok} in the unfiltered DescribeSnapshots "
        f"inventory after {timeout_s}s (last seen status={last_status})"
    )


def _wait_absent_from_inventory(ds, snapshot_id, timeout_s=120.0, interval_s=10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ds.describe_snapshots()
        if not any(s["SnapshotId"] == snapshot_id for s in resp.get("Snapshots", [])):
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} still present in the unfiltered DescribeSnapshots inventory "
        f"after {timeout_s}s"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _mad_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 12.0):
    """The shared directory fixture may be mutated by several checks in this run in
    sequence; a mutating call can transiently fail with DirectoryUnavailableException
    (another mutation still settling) or ServiceException. Retry with backoff rather
    than treat a transient collision as a real fidelity finding."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _delete_snapshot_with_retry(ds, snapshot_id, *, timeout_s: float, interval_s: float) -> None:
    """DeleteSnapshot can reject a snapshot that's still Creating (ClientException); retry
    with backoff within budget rather than waiting the full snapshot-creation time up front."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ds.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code in ("ClientException", "DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"DeleteSnapshot never succeeded for {snapshot_id} within {timeout_s}s "
        f"(snapshot likely still Creating; re-run to let it finish): {last_exc}"
    )


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


def _network_subnets(ctx):
    """Two distinct-AZ subnets of the run's shared network that Directory Service accepts; the
    network belongs to the run, so this check creates and deletes no VPC of its own."""
    ec2 = ctx.client("ec2")
    net = ctx.network()
    subnets = ec2.describe_subnets(SubnetIds=net.subnet_ids)["Subnets"]
    by_az = {}
    for s in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if s["State"] == "available" and s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError(f"the run's network has no two Directory Service AZ subnets: {net.subnet_ids}")
    return net.vpc_id, subnet_ids


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage={last_stage} after {timeout_s}s")


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    """An Active AWS Managed Microsoft AD directory with this check's own name, on the run's
    network, deleted in cleanup. Provisioning takes ~20-45 minutes, so the wait for Active
    allows up to an hour."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _network_subnets(ctx)
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_mad_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    return _wait_directory_stage(
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=3600.0, interval_s=30.0
    )["DirectoryId"]


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    run's network. DeleteDirectory is retried while the directory is still being created."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
