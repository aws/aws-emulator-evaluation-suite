"""global-cluster-membership-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-cluster-membership-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Global cluster: create -> add primary member -> rename -> remove member -> delete."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    global_id = ctx.unique_name("sim2real-behav-gc-")
    rds.create_global_cluster(
        GlobalClusterIdentifier=global_id,
        Engine="aurora-mysql",
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    current_global_id = global_id

    def _cleanup_global_cluster():
        if current_global_id is None:
            return
        try:
            rds.delete_global_cluster(GlobalClusterIdentifier=current_global_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "GlobalClusterNotFoundFault":
                raise

    ctx.on_cleanup(_cleanup_global_cluster)

    gc = _wait_global_cluster_status(ctx, global_id, {"available"})
    engine_version = gc["EngineVersion"]
    assert gc["GlobalClusterMembers"] == []

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

    gc = _wait_membership(ctx, global_id, expect_count=1)
    member = gc["GlobalClusterMembers"][0]
    assert member["DBClusterArn"] == cluster_arn
    assert member["IsWriter"] is True

    renamed_id = global_id + "-renamed"
    rds.modify_global_cluster(GlobalClusterIdentifier=global_id, NewGlobalClusterIdentifier=renamed_id)
    current_global_id = renamed_id
    gc = _wait_global_cluster_status(ctx, renamed_id, {"available"})
    assert gc["GlobalClusterIdentifier"] == renamed_id
    assert len(gc["GlobalClusterMembers"]) == 1

    # Negative: can't delete a global cluster while it still has a member.
    err = _client_error(lambda: rds.delete_global_cluster(GlobalClusterIdentifier=renamed_id))
    assert err.get("Code") == "InvalidGlobalClusterStateFault", (
        f"expected InvalidGlobalClusterStateFault, got {err.get('Code')!r}"
    )
    expected = f"Global Cluster {gc['GlobalClusterArn']} is not empty"
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Effect absent: the rejected delete must not have touched the membership or status.
    gc = rds.describe_global_clusters(GlobalClusterIdentifier=renamed_id)["GlobalClusters"][0]
    assert len(gc["GlobalClusterMembers"]) == 1, "a rejected delete must not remove the member"
    assert gc["Status"] == "available", "a rejected delete must not change the global cluster status"

    rds.remove_from_global_cluster(GlobalClusterIdentifier=renamed_id, DbClusterIdentifier=cluster_arn)
    gc = _wait_membership(ctx, renamed_id, expect_count=0)
    assert gc["GlobalClusterMembers"] == []

    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert not cluster.get("GlobalClusterIdentifier"), "cluster should no longer reference the global cluster"

    # Restore leg: with the member gone, the identical delete call that was just rejected now succeeds.
    rds.delete_global_cluster(GlobalClusterIdentifier=renamed_id)
    current_global_id = None
    final_code = _wait_global_cluster_gone(ctx, renamed_id)
    assert final_code == "GlobalClusterNotFoundFault", f"expected GlobalClusterNotFoundFault after delete, got {final_code!r}"

    # A mutation on the now-dead identifier also fails not-found, not some other error.
    mutation = _client_error(
        lambda: rds.modify_global_cluster(GlobalClusterIdentifier=renamed_id, NewGlobalClusterIdentifier=renamed_id + "-gone")
    )
    assert mutation.get("Code") == "GlobalClusterNotFoundFault", (
        f"expected mutation on deleted global cluster to fail not-found, got {mutation.get('Code')!r}"
    )
    expected_dead = f"Global cluster '{renamed_id}' not found"
    assert mutation.get("Message") == expected_dead, (
        f"expected message {expected_dead!r}, got {mutation.get('Message')!r}"
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
        try:
            return rds.describe_global_clusters(GlobalClusterIdentifier=global_id)["GlobalClusters"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] == "GlobalClusterNotFoundFault":
                # Right after ModifyGlobalCluster renames the identifier, the new name can take a
                # few seconds to become describable — treat that as "not ready yet" and keep
                # polling instead of letting a transient not-found blow up the whole check.
                return {"Status": "__not_yet_describable__"}
            raise

    return _poll_until(probe, lambda g: g["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)



def _wait_global_cluster_gone(ctx, global_id: str, timeout_s: float = 300.0, interval_s: float = 15.0) -> str:
    rds = ctx.client("rds")

    def probe():
        try:
            rds.describe_global_clusters(GlobalClusterIdentifier=global_id)
            return "available"
        except ClientError as e:
            return e.response["Error"]["Code"]

    return _poll_until(probe, lambda code: code == "GlobalClusterNotFoundFault", timeout_s=timeout_s, interval_s=interval_s)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
