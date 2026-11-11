"""automated-snapshot-listed-by-snapshot-type-for-instance-with-retention."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automated-snapshot-listed-by-snapshot-type-for-instance-with-retention"
GROUP = "snapshots"
SERVICES = ["rds"]

#: Smallest classes, in order of preference; the first orderable for the default version is used.
_CLASSES = ("db.t4g.micro", "db.t3.micro")
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, what, fn, pred, *, cap_s, interval_s=5, graded=False):
    """Poll fn() until pred(value). A deadline the run budget ended raises TimeoutError unless
    graded, when every missed deadline is an AssertionError."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if not graded and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not reached within {cap_s}s; last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _postgres_default_and_class(rds):
    """The default postgres version and the first of _CLASSES orderable on it."""
    version = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)[
        "DBEngineVersions"
    ][0]["EngineVersion"]
    for cls in _CLASSES:
        opts = rds.describe_orderable_db_instance_options(
            Engine="postgres", EngineVersion=version, DBInstanceClass=cls
        )["OrderableDBInstanceOptions"]
        if opts:
            return version, cls
    raise AssertionError(f"none of {_CLASSES!r} is orderable for postgres {version}")


def _retry_delete(fn, *, timeout_s=1500, interval_s=10):
    """A delete retried while a deleting instance still uses the resource; not-found is done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(("NotFound", "NotFoundFault")):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"resource was not deleted: {exc!r}") from exc
            time.sleep(interval_s)


def _delete_instance(rds, inst_id):
    """Delete the instance and its automated backups, waiting until it is gone."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return
        raise
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=inst_id, WaiterConfig={"Delay": 10, "MaxAttempts": 150}
    )


def _snapshots(rds, inst_id, snapshot_type):
    """(DBSnapshotIdentifier, DBInstanceIdentifier, SnapshotType, Status) of the instance's
    snapshots of one type."""
    return sorted(
        (s["DBSnapshotIdentifier"], s["DBInstanceIdentifier"], s["SnapshotType"], s["Status"])
        for page in rds.get_paginator("describe_db_snapshots").paginate(
            DBInstanceIdentifier=inst_id, SnapshotType=snapshot_type
        )
        for s in page["DBSnapshots"]
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An instance created with BackupRetentionPeriod 1 has an automated snapshot named rds:<id>-...
    that DescribeDBSnapshots lists under SnapshotType automated, and none under manual.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html
    """
    rds = ctx.client("rds")
    version, db_class = _postgres_default_and_class(rds)

    sng = ctx.unique_name("sim2real-behav-sng-")
    ctx.on_cleanup(lambda: _retry_delete(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=sng)))
    rds.create_db_subnet_group(
        DBSubnetGroupName=sng,
        DBSubnetGroupDescription="sim2real automated snapshot listing",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="postgres",
        EngineVersion=version,
        DBInstanceClass=db_class,
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername="sim2real",
        MasterUserPassword="S2r" + secrets.token_urlsafe(18),
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=_MANAGED_TAGS,
    )
    _poll(
        ctx,
        f"instance {inst_id} available",
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0][
            "DBInstanceStatus"
        ],
        lambda s: s == "available",
        cap_s=1800,
        interval_s=10,
    )

    automated = _poll(
        ctx,
        f"an available automated snapshot of {inst_id}",
        lambda: _snapshots(rds, inst_id, "automated"),
        lambda snaps: any(s[3] == "available" for s in snaps),
        cap_s=300,
        interval_s=10,
        graded=True,
    )
    for snap_id, owner, snap_type, _status in automated:
        assert (owner, snap_type) == (inst_id, "automated") and snap_id.startswith(
            f"rds:{inst_id}-"
        ), (
            f"SnapshotType=automated for {inst_id} must list only its automated snapshots named "
            f"rds:{inst_id}-<time>; got {automated!r}"
        )
    manual = _snapshots(rds, inst_id, "manual")
    assert manual == [], (
        f"no manual snapshot was taken of {inst_id}; SnapshotType=manual listed {manual!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
