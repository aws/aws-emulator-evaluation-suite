"""global-cluster-failover-and-switchover-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "global-cluster-failover-and-switchover-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FailoverGlobalCluster rejects a nonexistent target and SwitchoverGlobalCluster rejects the
    current primary as target, leaving global cluster membership unchanged."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    global_id = ctx.unique_name("sim2real-behav-gc-")
    rds.create_global_cluster(
        GlobalClusterIdentifier=global_id,
        Engine="aurora-mysql",
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_global_cluster_if_present(rds, global_id))
    gc = _wait_global_cluster_status(ctx, global_id, {"available"})
    engine_version = gc["EngineVersion"]

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        GlobalClusterIdentifier=global_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    cluster = _wait_cluster_status(ctx, cluster_id, {"available"})
    cluster_arn = cluster["DBClusterArn"]
    _wait_membership(ctx, global_id, expect_count=1)

    # Negative: FailoverGlobalCluster against a target that doesn't exist.
    bogus_arn = cluster_arn.rsplit(":", 1)[0] + ":sim2real-behav-does-not-exist"
    err = _client_error(
        lambda: rds.failover_global_cluster(
            GlobalClusterIdentifier=global_id, TargetDbClusterIdentifier=bogus_arn, AllowDataLoss=True
        )
    )
    assert err.get("Code") == "DBClusterNotFoundFault", f"expected DBClusterNotFoundFault, got {err.get('Code')!r}"
    expected = (
        f"A DB cluster with ARN {bogus_arn} doesn't exist. Choose another failover target and try again."
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Negative: SwitchoverGlobalCluster targeting the CURRENT primary itself is invalid;
    # a switchover target must be an existing secondary cluster. It is
    # rejected as a parameter-combination error (the target must differ from the current primary)
    # rather than a cluster/global-cluster state fault.
    err = _client_error(
        lambda: rds.switchover_global_cluster(GlobalClusterIdentifier=global_id, TargetDbClusterIdentifier=cluster_arn)
    )
    assert err.get("Code") == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {err.get('Code')!r}"
    )
    expected = "The specified switchover target is already the primary DB cluster."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Independent read: both rejected calls left membership exactly as it was.
    gc_after = rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"][0]
    members_after = gc_after["GlobalClusterMembers"]
    assert len(members_after) == 1, f"expected membership unaffected by rejected calls, got {members_after!r}"

    rds.remove_from_global_cluster(GlobalClusterIdentifier=global_id, DbClusterIdentifier=cluster_arn)
    _wait_membership(ctx, global_id, expect_count=0)


def _client_error(fn) -> dict:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_global_cluster_status(ctx, global_id: str, statuses: set[str], timeout_s: float = 600.0, interval_s: float = 15.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"][0]

    return _poll_until(probe, lambda g: g["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_membership(ctx, global_id: str, expect_count: int, timeout_s: float = 600.0, interval_s: float = 15.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"][0]

    return _poll_until(probe, lambda g: len(g["GlobalClusterMembers"]) == expect_count, timeout_s=timeout_s, interval_s=interval_s)


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    """Teardown: delete the cluster and wait until it is gone, so the subnet group (and any
    global cluster) it holds can be deleted after it. Tolerates a cluster already gone."""
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
    raise AssertionError(f"cluster {cluster_id} still present {timeout_s}s after DeleteDBCluster")


def _delete_global_cluster_if_present(rds, global_id: str) -> None:
    """Teardown: delete the global cluster, tolerating one the check body already deleted."""
    try:
        rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "GlobalClusterNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
