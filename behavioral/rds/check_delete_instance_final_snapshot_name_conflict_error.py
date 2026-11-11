"""delete-instance-final-snapshot-name-conflict-error."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-instance-final-snapshot-name-conflict-error"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstance with a FinalDBSnapshotIdentifier that names an existing snapshot is
    rejected with DBSnapshotAlreadyExists and leaves both unchanged; the same delete with a new
    final snapshot name succeeds."""
    instance_id = ctx.unique_name("sim2real-inst-")
    snap_id = ctx.unique_name("sim2real-snap-")
    rds = ctx.client("rds")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real!Pwd01",
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_id))
    _wait_for_instance_status(ctx, instance_id, "available", timeout_s=1200)

    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_snapshot(ctx, snap_id))
    original = _wait_for_snapshot_status(ctx, snap_id, "available", timeout_s=600)
    original_create_time = original["SnapshotCreateTime"]

    # Break exactly one thing: ask for a final snapshot whose name is already taken.
    code, msg = _client_error(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=False,
            FinalDBSnapshotIdentifier=snap_id,
        )
    )
    assert code == "DBSnapshotAlreadyExists", code
    assert msg == (
        f"Cannot create the snapshot because a snapshot with the identifier {snap_id} "
        "already exists."
    ), msg

    # (b) effect absent: the rejected call did not start deleting the instance, and did not
    # overwrite the pre-existing snapshot it collided with.
    desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert desc["DBInstanceStatus"] == "available", desc["DBInstanceStatus"]
    snaps = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"]
    assert len(snaps) == 1, snaps
    assert snaps[0]["SnapshotCreateTime"] == original_create_time, (
        f"the pre-existing snapshot was overwritten by the rejected call: expected create time "
        f"{original_create_time!r}, observed {snaps[0]['SnapshotCreateTime']!r}"
    )

    # (c) positive control: the identical DeleteDBInstance call, on the same instance, with the
    # name collision removed -- a genuinely new final snapshot name, not SkipFinalSnapshot --
    # succeeds. This attributes the earlier rejection specifically to the name conflict.
    new_snap_id = ctx.unique_name("sim2real-snap2-")
    ctx.on_cleanup(lambda: _safe_delete_snapshot(ctx, new_snap_id))
    _retry_delete_with_new_final_snapshot(ctx, instance_id, new_snap_id, timeout_s=300)
    _wait_for_instance_gone_or_deleting(ctx, instance_id, timeout_s=1200)
    _wait_for_snapshot_status(ctx, new_snap_id, "available", timeout_s=600)


def _client_error(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _wait_for_instance_status(ctx, instance_id: str, status: str, *, timeout_s: float) -> None:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ]

    _poll_until(probe, lambda s: s == status, timeout_s=timeout_s)


def _wait_for_instance_gone_or_deleting(ctx, instance_id: str, *, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")

    def probe():
        try:
            return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
                "DBInstanceStatus"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
                return "gone"
            raise

    _poll_until(probe, lambda s: s in ("gone", "deleting"), timeout_s=timeout_s)


def _wait_for_snapshot_status(ctx, snap_id: str, status: str, *, timeout_s: float) -> dict:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]

    return _poll_until(probe, lambda snap: snap["Status"] == status, timeout_s=timeout_s)


def _retry_delete_with_new_final_snapshot(
    ctx, instance_id: str, snap_id: str, *, timeout_s: float, interval_s: float = 15.0
) -> None:
    """DeleteDBInstance with a fresh FinalDBSnapshotIdentifier can transiently reject with
    InvalidDBInstanceState right after the earlier rejected attempt on the same instance;
    bounded-retry on that specific code, not a one-shot call."""
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=instance_id,
                SkipFinalSnapshot=False,
                FinalDBSnapshotIdentifier=snap_id,
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidDBInstanceState", "InvalidDBInstanceStateFault"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"DeleteDBInstance never became valid within {timeout_s}s: {last_exc}")


def _safe_delete_instance(ctx, instance_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DBInstanceNotFound",
            "DBInstanceNotFoundFault",
            "InvalidDBInstanceState",
            "InvalidDBInstanceStateFault",
        ):
            raise


def _safe_delete_snapshot(ctx, snap_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBSnapshotNotFound", "DBSnapshotNotFoundFault"):
            raise


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
