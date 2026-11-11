"""snapshot-timestamp-precision-round-trip."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-timestamp-precision-round-trip"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SnapshotCreateTime on a manual DB snapshot is stable and identical (no drift, no
    truncation of sub-second precision) across repeated DescribeDBSnapshots calls."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-snaptime-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    snapshot_id = ctx.unique_name("sim2real-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=instance_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    snapshot = _wait_snapshot_status(ctx, snapshot_id, "available", timeout_s=1200)

    first_time = snapshot["SnapshotCreateTime"]
    assert first_time is not None, (
        f"SnapshotCreateTime was not populated on available snapshot {snapshot_id}"
    )

    _poll_create_time_stable(rds, snapshot_id, first_time)


def _poll_create_time_stable(
    rds, snapshot_id: str, baseline, *, min_elapsed_s: float = 6.0, timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> None:
    """Re-read on a bounded real-clock schedule, asserting on every sample, until at least
    min_elapsed_s has passed since the baseline was captured — never a single fixed sleep
    followed by one check at the end."""
    start = time.monotonic()
    while True:
        time.sleep(interval_s)
        again = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
        assert again["SnapshotCreateTime"] == baseline, (
            f"SnapshotCreateTime drifted across reads: {baseline!r} vs "
            f"{again['SnapshotCreateTime']!r}"
        )
        elapsed = time.monotonic() - start
        if elapsed >= min_elapsed_s or elapsed >= timeout_s:
            return


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_snapshot_status(ctx, snapshot_id, target_status, timeout_s=1200, poll_s=15) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"snapshot {snapshot_id} never reached {target_status!r}, "
        f"last status {last and last['Status']!r}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
