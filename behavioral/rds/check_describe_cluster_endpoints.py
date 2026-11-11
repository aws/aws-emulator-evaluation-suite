"""describe-cluster-endpoints."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-cluster-endpoints"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _cluster(rds, cid):
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=cid).get("DBClusters", [])
        return clusters[0] if clusters else None
    except ClientError:
        return None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterEndpoints: a real Aurora cluster automatically gets a writer cluster
    endpoint once available, filtered by DBClusterIdentifier. Error boundary: an unknown
    DBClusterIdentifier rejects with DBClusterNotFoundFault.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword=_make_password(),
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: _cluster(rds, cluster_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} available",
    )

    def probe():
        resp = rds.describe_db_cluster_endpoints(DBClusterIdentifier=cluster_id)
        return resp.get("DBClusterEndpoints", [])

    endpoints = probe()
    endpoints = _poll_until(
        probe,
        lambda eps: len(eps) > 0,
        timeout_s=120,
        interval_s=5,
        description=f"cluster endpoints for {cluster_id}",
    )
    assert any(e.get("EndpointType") == "WRITER" for e in endpoints), endpoints
    assert all(e["DBClusterIdentifier"] == cluster_id for e in endpoints), endpoints

    bogus_cluster = ctx.unique_name("sim2real-behav-clu-missing-")
    code, message = _client_error(
        lambda: rds.describe_db_cluster_endpoints(DBClusterIdentifier=bogus_cluster)
    )
    assert code == "DBClusterNotFoundFault", f"unexpected error code: {code}"
    assert message == (
        f"The source cluster could not be found or cannot be accessed: {bogus_cluster}"
    ), message


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
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
