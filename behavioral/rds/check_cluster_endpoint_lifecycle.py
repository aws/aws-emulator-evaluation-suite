"""cluster-endpoint-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-endpoint-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Custom cluster endpoint: creating -> available -> modifying -> deleting, then not-found."""
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx)

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    _wait_cluster_status(ctx, cluster_id, {"available"})

    endpoint_id = ctx.unique_name("sim2real-behav-ep-")
    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=endpoint_id,
        EndpointType="READER",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _safe_delete_endpoint():
        try:
            rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "DBClusterEndpointNotFoundFault":
                raise

    ctx.on_cleanup(_safe_delete_endpoint)

    endpoint = _wait_endpoint_status(ctx, endpoint_id, {"available"})
    assert endpoint["CustomEndpointType"] == "READER", (
        f"expected CustomEndpointType READER, got {endpoint['CustomEndpointType']!r}"
    )

    rds.modify_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id, EndpointType="ANY")
    endpoint = _wait_endpoint_status(ctx, endpoint_id, {"available"})
    assert endpoint["CustomEndpointType"] == "ANY", f"expected ANY, got {endpoint['CustomEndpointType']!r}"

    rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
    _wait_endpoint_gone(ctx, endpoint_id)

    # Negative: modify/describe after deletion is rejected.
    code, message = _error_detail(
        lambda: rds.modify_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id, EndpointType="READER")
    )
    assert code == "DBClusterEndpointNotFoundFault", f"expected DBClusterEndpointNotFoundFault, got {code!r}"
    expected = f"DBClusterEndpoint {endpoint_id} not found"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Note: unlike modify, describe treats DBClusterEndpointIdentifier as a filter and
    # simply returns an empty list for a deleted/unknown endpoint rather than raising.
    resp = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)
    assert resp["DBClusterEndpoints"] == [], f"expected no endpoints, got {resp['DBClusterEndpoints']!r}"


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
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 900.0) -> None:
    """Delete the cluster and wait until it is gone, so the subnet group teardown after it
    does not race a cluster still in "deleting"."""
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(15)
    raise AssertionError(f"cluster {cluster_id} was not deleted within {timeout_s}s")


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


def _wait_endpoint_status(ctx, endpoint_id: str, statuses: set[str], timeout_s: float = 600.0, interval_s: float = 15.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        resp = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)
        eps = resp["DBClusterEndpoints"]
        assert len(eps) == 1, f"expected exactly 1 endpoint named {endpoint_id!r}, got {len(eps)}"
        return eps[0]

    return _poll_until(probe, lambda e: e["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_endpoint_gone(ctx, endpoint_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterEndpointNotFoundFault":
                return
            raise
        if not resp["DBClusterEndpoints"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {endpoint_id} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
