"""snapshot-create-time-timestamp-precision-preserved."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snapshot-create-time-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SnapshotCreateTime captured when a manual snapshot finishes provisioning is returned as
    the exact same timestamp value (same datetime, same tzinfo, no drift/truncation) on every
    subsequent DescribeDBSnapshots call, including a read taken a few seconds later."""
    rds = ctx.client("rds")

    instance_id = ctx.unique_name("sim2real-snaptime-")
    password = _random_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )
    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=instance_id,
        WaiterConfig={"Delay": 2, "MaxAttempts": 900},
    )

    snapshot_id = ctx.unique_name("sim2real-snap-")
    rds.create_db_snapshot(
        DBInstanceIdentifier=instance_id,
        DBSnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    rds.get_waiter("db_snapshot_available").wait(
        DBSnapshotIdentifier=snapshot_id,
        WaiterConfig={"Delay": 2, "MaxAttempts": 300},
    )

    first = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
    create_time_1 = first["SnapshotCreateTime"]
    assert create_time_1 is not None, "SnapshotCreateTime was not populated on an available snapshot"

    # Re-read repeatedly over a bounded window of real wall-clock time: each sample must show
    # the identical value, not a re-derived/re-rounded one. This fails fast on the first sample
    # that drifts, rather than sleeping a fixed amount and checking once at the end.
    create_time_2 = _poll_snapshot_create_time_stable(rds, snapshot_id, create_time_1)

    assert create_time_1.utcoffset() == create_time_2.utcoffset(), (
        "SnapshotCreateTime tzinfo/offset changed between reads"
    )


def _random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(20))


def _poll_snapshot_create_time_stable(
    rds,
    snapshot_id: str,
    baseline,
    *,
    min_elapsed_s: float = 6.0,
    timeout_s: float = 30.0,
    interval_s: float = 3.0,
):
    """Poll DescribeDBSnapshots every `interval_s` seconds, asserting on EVERY sample that
    SnapshotCreateTime still equals `baseline`, until at least `min_elapsed_s` of real
    wall-clock time has elapsed since the baseline was captured (bounded overall by
    `timeout_s`). Returns the last observed value. Raises immediately the moment a sample
    drifts, instead of waiting out a fixed sleep before checking anything."""
    start = time.monotonic()
    latest = baseline
    while True:
        time.sleep(interval_s)
        current = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
        latest = current["SnapshotCreateTime"]
        assert latest == baseline, (
            f"SnapshotCreateTime drifted between reads: baseline={baseline!r} now={latest!r}"
        )
        elapsed = time.monotonic() - start
        if elapsed >= min_elapsed_s or elapsed >= timeout_s:
            return latest


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
