"""cluster-read-replica-promotion."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-read-replica-promotion"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A secondary Aurora cluster (ReplicationSourceIdentifier) is promoted to a standalone cluster."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)
    cluster_pg = _create_binlog_cluster_parameter_group(ctx)

    primary_id = ctx.unique_name("sim2real-behav-pri-")
    rds.create_db_cluster(
        DBClusterIdentifier=primary_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        DBClusterParameterGroupName=cluster_pg,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, primary_id))
    primary = _wait_cluster_status(ctx, primary_id, {"available"})
    primary_arn = primary["DBClusterArn"]

    # Negative: promoting a cluster that isn't a read replica at all is rejected.
    code, message = _error_detail(lambda: rds.promote_read_replica_db_cluster(DBClusterIdentifier=primary_id))
    assert code == "InvalidDBClusterStateFault", f"expected InvalidDBClusterStateFault, got {code!r}"
    expected = "You cannot promote a DB cluster that is not a read replica."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Aurora MySQL cluster-level replication (ReplicationSourceIdentifier) ships binlog from the
    # SOURCE cluster's writer instance -- a source with no writer has nothing to ship, and real AWS
    # rejects CreateDBCluster for the replica with "doesn't have a writer instance". Give the
    # primary one before attempting the replica.
    primary_writer_id = ctx.unique_name("sim2real-behav-pri-w-")
    rds.create_db_instance(
        DBInstanceIdentifier=primary_writer_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=primary_id,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, primary_writer_id))
    _wait_instance_status(ctx, primary_writer_id, {"available"})

    secondary_id = ctx.unique_name("sim2real-behav-sec-")
    try:
        rds.create_db_cluster(
            DBClusterIdentifier=secondary_id,
            Engine="aurora-mysql",
            ReplicationSourceIdentifier=primary_arn,
            DBSubnetGroupName=subnet_group,
            Tags=_MANAGED_TAGS,
        )
    except ClientError as e:
        raise AssertionError(f"Aurora cluster read replica via ReplicationSourceIdentifier unavailable here: {e}")
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, secondary_id))
    secondary = _wait_cluster_status(ctx, secondary_id, {"available"}, timeout_s=1500.0)
    assert secondary.get("ReplicationSourceIdentifier") == primary_arn

    rds.promote_read_replica_db_cluster(DBClusterIdentifier=secondary_id)
    promoted = _wait_promoted(ctx, secondary_id, timeout_s=1200.0)
    assert not promoted.get("ReplicationSourceIdentifier"), "replication source should be cleared after promotion"
    assert promoted["Status"] == "available"


def _error_detail(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call succeeded; expected a rejection")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets"
    return ids


def _create_binlog_cluster_parameter_group(ctx) -> str:
    """Aurora MySQL cluster-level replication (ReplicationSourceIdentifier) ships binlog from the
    source cluster's writer; a cluster's default parameter group leaves binlog_format unset, and
    CreateDBCluster for the replica rejects the source with "doesn't have binlogs enabled"."""
    rds = ctx.client("rds")
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql", DefaultOnly=True)["DBEngineVersions"]
    assert versions, "no aurora-mysql engine version is orderable in this region"
    family = versions[0]["DBParameterGroupFamily"]

    name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="sim2real behavioral check: enable binlog for cluster replication",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=name))
    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=name,
        Parameters=[{"ParameterName": "binlog_format", "ParameterValue": "ROW", "ApplyMethod": "pending-reboot"}],
    )
    return name


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_promoted(ctx, cluster_id: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(
        probe,
        lambda c: c["Status"] == "available" and not c.get("ReplicationSourceIdentifier"),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _delete_instance_and_wait(rds, instance_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    """Delete the instance and wait until it is gone, so the cluster, parameter group and subnet
    group torn down after it are no longer in use."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} still exists {timeout_s}s after DeleteDBInstance")


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    """Delete the cluster and wait until it is gone, so the parameter group and subnet group torn
    down after it are no longer in use."""
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} still exists {timeout_s}s after DeleteDBCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
