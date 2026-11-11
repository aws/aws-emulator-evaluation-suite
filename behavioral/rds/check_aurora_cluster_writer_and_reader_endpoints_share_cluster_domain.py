"""aurora-cluster-writer-and-reader-endpoints-share-cluster-domain."""

from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aurora-cluster-writer-and-reader-endpoints-share-cluster-domain"
GROUP = "cluster-endpoint"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The poll then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, what, fn, pred, *, cap_s, interval_s=5):
    """Poll fn() until pred(value); a deadline the run budget ended raises TimeoutError."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not reached within {cap_s}s; last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _cluster(rds, cl_id):
    """DescribeDBClusters for one id, or None once it no longer exists."""
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cl_id)["DBClusters"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            return None
        raise


def _delete_cluster(rds, cl_id, *, wait_s=900):
    """Delete the cluster with no final snapshot and wait until it is gone."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cl_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    while _cluster(rds, cl_id) is not None:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"cluster {cl_id} still exists {wait_s}s after DeleteDBCluster")
        time.sleep(5)


def _delete_subnet_group(rds, name, *, timeout_s=900):
    """Delete a subnet group, retrying while a deleting cluster still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Aurora cluster's Endpoint and ReaderEndpoint share one suffix.

    Endpoint is <id>.cluster-<suffix> and ReaderEndpoint <id>.cluster-ro-<suffix>, each a published
    RDS host in the cluster's region, and DescribeDBClusterEndpoints lists exactly those two.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html
    """
    rds = ctx.client("rds")

    sng = ctx.unique_name("sim2real-behav-sng-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, sng))
    rds.create_db_subnet_group(
        DBSubnetGroupName=sng,
        DBSubnetGroupDescription="sim2real aurora cluster endpoints",
        SubnetIds=ctx.network().subnet_ids,
        Tags=_MANAGED_TAGS,
    )

    cl_id = ctx.unique_name("sim2real-behav-cl-")
    ctx.on_cleanup(lambda: _delete_cluster(rds, cl_id))
    rds.create_db_cluster(
        DBClusterIdentifier=cl_id,
        Engine="aurora-postgresql",
        MasterUsername="sim2real",
        MasterUserPassword="S2r" + secrets.token_urlsafe(18),
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
    )
    cluster = _poll(
        ctx,
        f"cluster {cl_id} available",
        lambda: _cluster(rds, cl_id),
        lambda c: c is not None and c["Status"] == "available",
        cap_s=1200,
        interval_s=10,
    )

    writer, reader = cluster.get("Endpoint", ""), cluster.get("ReaderEndpoint", "")
    w_prefix, r_prefix = f"{cl_id}.cluster-", f"{cl_id}.cluster-ro-"
    suffix = writer[len(w_prefix) :] if writer.startswith(w_prefix) else ""
    assert suffix and reader == r_prefix + suffix, (
        f"Endpoint must be {w_prefix}<suffix> and ReaderEndpoint {r_prefix}<same suffix>; "
        f"got Endpoint={writer!r}, ReaderEndpoint={reader!r}"
    )
    for host in (writer, reader):
        problem = ctx.published_url_mismatch(f"https://{host}", labels=("rds", ctx.region))
        assert problem is None, problem

    listed = rds.describe_db_cluster_endpoints(DBClusterIdentifier=cl_id)["DBClusterEndpoints"]
    by_type = sorted((e["EndpointType"], e["Endpoint"]) for e in listed)
    want = sorted([("WRITER", writer), ("READER", reader)])
    assert by_type == want, (
        f"DescribeDBClusterEndpoints must list the WRITER and READER endpoints {want!r}; "
        f"got {by_type!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
