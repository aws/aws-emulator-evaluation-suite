"""duplicate-cluster-identifier-creation-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-cluster-identifier-creation-rejected"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster with an identifier that already exists is rejected, even with different parameters."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    _wait_cluster_status(ctx, cluster_id, {"available"})

    # Same identifier, deliberately different engine/admin user: still rejected on identity, not content.
    err = _client_error(
        lambda: rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-postgresql",
            MasterUsername="otheradmin",
            MasterUserPassword=_MASTER_PW,
            DBSubnetGroupName=subnet_group,
        )
    )
    assert err.get("Code") == "DBClusterAlreadyExistsFault", (
        f"expected DBClusterAlreadyExistsFault, got {err.get('Code')!r}"
    )
    assert err.get("Message") == "DB Cluster already exists", (
        f"expected message 'DB Cluster already exists', got {err.get('Message')!r}"
    )

    # The original cluster is untouched by the rejected duplicate attempt.
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Engine"] == "aurora-mysql", f"expected Engine aurora-mysql, got {cluster['Engine']!r}"
    assert cluster["MasterUsername"] == "simadmin", (
        f"expected MasterUsername simadmin, got {cluster['MasterUsername']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a duplicate identifier real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected DBClusterAlreadyExistsFault, but the call SUCCEEDED: {result!r}")


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
