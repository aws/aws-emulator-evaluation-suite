"""e2e-http-data-api-toggle-flow."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-http-data-api-toggle-flow"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling the Data API HTTP endpoint on an Aurora cluster flips HttpEndpointEnabled
    from False to True, and DisableHttpEndpoint flips it back -- asserting the observed
    consequence on DescribeDBClusters, not merely that the toggle calls returned 200."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-httpapi-")
    password = _rand_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-httpapi"},
        ],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=1200)
    cluster_arn = cluster["DBClusterArn"]
    assert cluster["HttpEndpointEnabled"] is False, "cluster was not created with Data API disabled"

    rds.enable_http_endpoint(ResourceArn=cluster_arn)
    cluster = _wait_http_endpoint(ctx, cluster_id, expected=True, timeout_s=180)
    assert cluster["HttpEndpointEnabled"] is True, (
        f"expected HttpEndpointEnabled=True after EnableHttpEndpoint, got {cluster['HttpEndpointEnabled']!r}"
    )
    # The flag flips promptly, but the underlying Data API resource can still be settling;
    # wait for the cluster to report "available" again before mutating it further.
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=180)

    _retry_disable_http_endpoint(ctx, cluster_arn, timeout_s=300)
    cluster = _wait_http_endpoint(ctx, cluster_id, expected=False, timeout_s=180)
    assert cluster["HttpEndpointEnabled"] is False, (
        f"expected HttpEndpointEnabled=False after DisableHttpEndpoint, got {cluster['HttpEndpointEnabled']!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_disable_http_endpoint(ctx, cluster_arn, timeout_s=300, poll_s=2) -> None:
    """DisableHttpEndpoint can transiently reject with InvalidResourceStateFault while the
    just-enabled Data API resource is still settling; bounded-retry rather than fail once."""
    import botocore.exceptions

    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.disable_http_endpoint(ResourceArn=cluster_arn)
            return
        except botocore.exceptions.ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidResourceStateFault":
                raise
            last_exc = exc
            time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError("DisableHttpEndpoint while the Data API settles: the run budget ended first; not graded")
    raise AssertionError(f"DisableHttpEndpoint never became valid within {timeout_s}s: {last_exc}")



def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_http_endpoint(ctx, cluster_id, expected: bool, timeout_s=180, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["HttpEndpointEnabled"] is expected:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"cluster {cluster_id} HttpEndpointEnabled={expected!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"HttpEndpointEnabled never became {expected!r}, "
        f"last observed {last and last['HttpEndpointEnabled']!r}"
    )


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
