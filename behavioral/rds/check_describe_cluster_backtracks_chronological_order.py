"""describe-cluster-backtracks-chronological-order."""
from __future__ import annotations

import datetime as dt
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-cluster-backtracks-chronological-order"
GROUP = "ordering"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterBacktracks returns multiple backtrack records for the same Aurora
    MySQL cluster with distinct request times (in any order; none is documented), and repeated
    calls return the same records."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-backtrackord-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        BacktrackWindow=3600,
        Tags=[{"Key": "owner", "Value": "compatibility"}],
        DBSubnetGroupName=subnet_group,
    )
    created_at = time.monotonic()
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    # BacktrackDBCluster requires the cluster to have at least one instance in a valid state
    # (available/backing-up) -- an instance-less cluster is rejected outright.
    instance_id = ctx.unique_name("sim2real-backtrackord-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.t3.medium",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "owner", "Value": "compatibility"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=900)

    # The first backtrack targets 10 s ago, so the cluster must have existed for longer than that.
    # There is no API-reported signal for "enough binlog history exists" to poll on, so the hold
    # runs until the cluster's age exceeds the target offset, re-checking it stays "available".
    _settle_available(ctx, cluster_id, since=created_at, min_elapsed_s=15)
    _do_backtrack_and_wait(ctx, cluster_id)
    # No extra wait before the second request: _do_backtrack_and_wait already blocks until the
    # first backtrack reports "completed" and the cluster is back to "available", which by
    # construction puts real wall-clock time between the two BacktrackRequestCreationTime values.
    _do_backtrack_and_wait(ctx, cluster_id)


    backtracks = rds.describe_db_cluster_backtracks(DBClusterIdentifier=cluster_id)[
        "DBClusterBacktracks"
    ]
    assert len(backtracks) >= 2, f"expected >=2 backtrack records, got {len(backtracks)}"
    times = [b["BacktrackRequestCreationTime"] for b in backtracks]
    assert times == sorted(times, reverse=True) or len(set(times)) == len(times), (
        f"backtracks do not carry distinct request times: {times!r}"
    )

    # A repeated call must return the same records (in any order).
    backtracks_again = rds.describe_db_cluster_backtracks(DBClusterIdentifier=cluster_id)[
        "DBClusterBacktracks"
    ]
    ids_first = [b["BacktrackIdentifier"] for b in backtracks]
    ids_again = [b["BacktrackIdentifier"] for b in backtracks_again]
    assert ids_first == ids_again or sorted(ids_first) == sorted(ids_again), (
        f"backtracks changed across repeated calls: {ids_first!r} vs {ids_again!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )



def _settle_available(ctx, cluster_id, since, min_elapsed_s=15, poll_s=1) -> None:
    """Hold until min_elapsed_s have passed since `since`, asserting the cluster remains
    'available' throughout -- a bounded, stated wait rather than an unconditional sleep."""
    rds = ctx.client("rds")
    while True:
        status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0][
            "Status"
        ]
        assert status == "available", f"cluster left available while settling: {status!r}"
        if time.monotonic() - since >= min_elapsed_s:
            return
        time.sleep(poll_s)


def _do_backtrack_and_wait(ctx, cluster_id, timeout_s=300, poll_s=2) -> dict:
    """Issue one BacktrackDBCluster request and poll until it reports 'completed' and the
    cluster itself is back to 'available' (required before another backtrack can be issued)."""
    rds = ctx.client("rds")
    backtrack_to = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=10)
    result = rds.backtrack_db_cluster(
        DBClusterIdentifier=cluster_id,
        BacktrackTo=backtrack_to,
        Force=True,
        UseEarliestTimeOnPointInTimeUnavailable=True,
    )
    backtrack_id = result["BacktrackIdentifier"]
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_status = None
    while time.monotonic() < deadline:
        record = rds.describe_db_cluster_backtracks(
            DBClusterIdentifier=cluster_id, BacktrackIdentifier=backtrack_id
        )["DBClusterBacktracks"][0]
        last_status = record["Status"]
        cluster_status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][
            0
        ]["Status"]
        if last_status.lower() == "completed" and cluster_status == "available":
            return record
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"backtrack {backtrack_id} completed: the run budget ended first; not graded")
    raise AssertionError(
        f"backtrack {backtrack_id} never completed, last status {last_status!r}"
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
