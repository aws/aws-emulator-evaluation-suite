"""delete-global-cluster-with-member."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "delete-global-cluster-with-member"
GROUP = 'global_clusters'
SERVICES = ['rds']

ERR_INVALID_GLOBAL_CLUSTER_STATE = "InvalidGlobalClusterStateFault"
ERR_GLOBAL_CLUSTER_NOT_FOUND = "GlobalClusterNotFoundFault"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("call unexpectedly succeeded")


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_cluster(rds, cluster_id):
    try:
        resp = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
    except ClientError:
        return None
    clusters = resp.get("DBClusters", [])
    return clusters[0] if clusters else None


def _describe_global_cluster(rds, global_id):
    try:
        resp = rds.describe_global_clusters(GlobalClusterIdentifier=global_id)
    except ClientError:
        return None
    clusters = resp.get("GlobalClusters", [])
    return clusters[0] if clusters else None


def _default_subnet_ids(ctx, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets"
    return ids


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGlobalCluster with an attached member fails InvalidGlobalClusterStateFault.

    After the member is detached the same call succeeds and the global cluster reads as not found.
    """
    rds = ctx.client("rds")
    account = ctx.client("sts").get_caller_identity()["Account"]
    tags_spec = [{"Key": "sim2real", "Value": "true"}]

    subnet_group = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=_default_subnet_ids(ctx),
        Tags=tags_spec,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group))

    global_id = ctx.unique_name("sim2real-behav-gclu-")
    rds.create_global_cluster(GlobalClusterIdentifier=global_id, Engine="aurora-mysql", Tags=tags_spec)
    ctx.on_cleanup(lambda: _unless_gone(lambda: rds.delete_global_cluster(GlobalClusterIdentifier=global_id), "GlobalClusterNotFoundFault"))
    global_cluster = _poll_until(
        lambda: _describe_global_cluster(rds, global_id),
        lambda g: g is not None and g.get("Status") == "available",
        timeout_s=300,
        interval_s=5,
        description=f"global cluster {global_id} available",
    )
    engine_version = global_cluster["EngineVersion"]

    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        EngineVersion=engine_version,
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        BackupRetentionPeriod=1,
        DBSubnetGroupName=subnet_group,
        GlobalClusterIdentifier=global_id,
        Tags=tags_spec,
    )
    ctx.on_cleanup(
        lambda: _delete_cluster_and_wait(rds, cluster_id)
    )
    _poll_until(
        lambda: _describe_cluster(rds, cluster_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=600,
        interval_s=5,
        description=f"cluster {cluster_id} available",
    )

    code, message = _error_code(
        lambda: rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    )
    assert code == ERR_INVALID_GLOBAL_CLUSTER_STATE, f"unexpected error code: {code}"
    assert message == f"Global Cluster arn:aws:rds::{account}:global-cluster:{global_id} is not empty", message

    # Detach the member; the state conflict is resolvable, not permanent.
    rds.remove_from_global_cluster(
        GlobalClusterIdentifier=global_id,
        DbClusterIdentifier=f"arn:aws:rds:{ctx.region}:{account}:cluster:{cluster_id}",
    )
    _poll_until(
        lambda: _describe_cluster(rds, cluster_id),
        lambda c: c is not None and not c.get("GlobalClusterIdentifier"),
        timeout_s=180,
        interval_s=5,
        description=f"cluster {cluster_id} detached from global cluster",
    )

    # The identical call now succeeds; the global cluster is then gone and unusable.
    rds.delete_global_cluster(GlobalClusterIdentifier=global_id)
    gone_code, gone_message = _error_code(lambda: rds.modify_global_cluster(GlobalClusterIdentifier=global_id, NewGlobalClusterIdentifier=global_id))
    assert gone_code == ERR_GLOBAL_CLUSTER_NOT_FOUND, f"unexpected error code after delete: {gone_code}"
    assert gone_message == f"Global cluster '{global_id}' not found", gone_message
    _poll_until(
        lambda: _describe_global_cluster(rds, global_id),
        lambda g: g is None,
        timeout_s=120,
        interval_s=5,
        description=f"global cluster {global_id} gone from an independent read",
    )


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


def _delete_cluster_and_wait(rds, cluster_id, timeout_s=840.0):
    """Delete a DB cluster and wait until it is gone, so the subnet group it uses can be deleted."""
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBClusterNotFoundFault":
            raise
    # Polled rather than the db_cluster_deleted waiter, which fails outright on the "creating" state
    # a cluster deleted while still provisioning reports first.
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"DB cluster {cluster_id} still {status!r} {timeout_s:.0f}s after DeleteDBCluster")
        time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
