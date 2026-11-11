"""global-cluster-delete-with-member-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "global-cluster-delete-with-member-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGlobalCluster is rejected while a DB cluster is still a member; the rejection leaves
    the global cluster and its member intact, and the identical delete succeeds once the member is
    detached — a resolvable state conflict, not a permanent one."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    global_id = ctx.unique_name("sim2real-behav-gc-")
    rds.create_global_cluster(GlobalClusterIdentifier=global_id, Engine="aurora-mysql", StorageEncrypted=True)
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
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    cluster = _wait_cluster_status(ctx, cluster_id, {"available"})
    cluster_arn = cluster["DBClusterArn"]
    _wait_membership(ctx, global_id, expect_count=1)

    err = _client_error(lambda: rds.delete_global_cluster(GlobalClusterIdentifier=global_id))
    assert err.get("Code") == "InvalidGlobalClusterStateFault", (
        f"expected InvalidGlobalClusterStateFault, got {err.get('Code')!r}"
    )
    expected = f"Global Cluster {gc['GlobalClusterArn']} is not empty"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Effect absent: the rejected delete must not have touched the global cluster or its member.
    gc = _describe_global_cluster(ctx, global_id)
    assert gc is not None, "global cluster must still exist after the rejected delete"
    assert len(gc["GlobalClusterMembers"]) == 1, "member must still be attached after the rejected delete"

    # Once detached, the global cluster can be deleted (state conflict is resolvable, not permanent):
    # the SAME delete call that was just rejected now succeeds.
    rds.remove_from_global_cluster(GlobalClusterIdentifier=global_id, DbClusterIdentifier=cluster_arn)
    _wait_membership(ctx, global_id, expect_count=0)

    rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    _wait_global_cluster_deleted(ctx, global_id)

    # The dead id is unusable for further mutation, not just absent from a read.
    dead = _client_error(
        lambda: rds.modify_global_cluster(GlobalClusterIdentifier=global_id, NewGlobalClusterIdentifier=global_id + "-x")
    )
    assert dead.get("Code") == "GlobalClusterNotFoundFault", (
        f"expected GlobalClusterNotFoundFault, got {dead.get('Code')!r}"
    )
    expected_dead = f"Global cluster '{global_id}' not found"
    assert dead.get("Message") == expected_dead, (
        f"expected message {expected_dead!r}, got {dead.get('Message')!r}"
    )


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _create_subnet_group(ctx) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real behavioral check", SubnetIds=_default_subnet_ids(ctx)
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


def _describe_global_cluster(ctx, global_id: str) -> dict[str, Any] | None:
    rds = ctx.client("rds")
    try:
        clusters = rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "GlobalClusterNotFoundFault":
            return None
        raise
    return clusters[0] if clusters else None


def _wait_global_cluster_deleted(ctx, global_id: str, timeout_s: float = 300.0, interval_s: float = 15.0) -> None:
    _poll_until(
        lambda: _describe_global_cluster(ctx, global_id),
        lambda gc: gc is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


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
