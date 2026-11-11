"""failover-cluster-with-no-db-instances-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failover-cluster-with-no-db-instances-rejected"
GROUP = "high-availability"
SERVICES = ["rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


def _poll(fn, pred, *, timeout_s, interval_s=5.0):
    """Poll fn() until pred(value); raises at the deadline naming the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last saw {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _cluster(rds, cl_id):
    try:
        found = rds.describe_db_clusters(DBClusterIdentifier=cl_id)["DBClusters"]
        return found[0] if found else None
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            return None
        raise


_RETRYABLE = ("DependencyViolation", "InvalidDBClusterStateFault", "InvalidDBSubnetGroupStateFault")


def _retrying_delete(undo, *not_found, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            undo()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in not_found:
                return
            if code not in _RETRYABLE or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _default_engine_version(rds, engine):
    """The engine's current default version. Derived, never pinned: the default moves."""
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)["DBEngineVersions"]
    assert versions, f"no default {engine!r} engine version is orderable in this region"
    return versions[0]["EngineVersion"]


def _network(ctx):
    rds = ctx.client("rds")
    net = ctx.network()
    group = ctx.unique_name("sim2real-net-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group, DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=net.subnet_ids, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retrying_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group),
        "DBSubnetGroupNotFoundFault"))
    return group


def _error_detail(fn):
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS rejects FailoverDBCluster on a cluster with no DB instances, but it SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """FailoverDBCluster on an Aurora PostgreSQL cluster with no DB instances is rejected with its
    exact code and message — there is no writer and no reader to promote — and the cluster still
    accepts an unrelated modification.
    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Managing.FaultTolerance.html
    """
    rds = ctx.client("rds")
    engine = "aurora-postgresql"
    version = _default_engine_version(rds, engine)
    subnet_group = _network(ctx)

    cl_id = ctx.unique_name("sim2real-behav-clus-")
    rds.create_db_cluster(
        DBClusterIdentifier=cl_id, Engine=engine, EngineVersion=version,
        MasterUsername="sim2real", MasterUserPassword="S2rNoMembersPwd12345",
        DatabaseName="sim2real", BackupRetentionPeriod=1,
        DBSubnetGroupName=subnet_group, DeletionProtection=False, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retrying_delete(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True),
        "DBClusterNotFoundFault"))

    cluster = _poll(lambda: _cluster(rds, cl_id),
                    lambda c: c is not None and c.get("Status") == "available", timeout_s=300)
    assert cluster.get("DBClusterMembers") == [], (
        f"this check needs a cluster with no DB instances; it has "
        f"{cluster.get('DBClusterMembers')!r}"
    )

    code, message = _error_detail(lambda: rds.failover_db_cluster(DBClusterIdentifier=cl_id))
    assert code == "InvalidDBClusterStateFault", f"unexpected error code {code!r}: {message!r}"
    expected = (
        f"Database cluster:{cl_id} should have at least two database instances for failover."
    )
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Control: an unrelated modification still succeeds (the cluster is not broadly stuck).
    rds.modify_db_cluster(DBClusterIdentifier=cl_id, BackupRetentionPeriod=3, ApplyImmediately=True)
    _poll(lambda: _cluster(rds, cl_id),
          lambda c: c is not None and c.get("BackupRetentionPeriod") == 3, timeout_s=180)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
