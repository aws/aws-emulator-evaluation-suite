"""cluster-endpoint-duplicate-name-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-endpoint-duplicate-name-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CreateDBClusterEndpoint with an identifier in use fails with DBClusterEndpointAlreadyExistsFault and
    leaves one endpoint under that name; once the holder is deleted the identical call succeeds, and a
    new identifier in the same cluster succeeds too."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-clep-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    endpoint_id = ctx.unique_name("sim2real-ep-")
    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=endpoint_id,
        EndpointType="ANY",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
    )
    existing = _wait_endpoint_status(ctx, endpoint_id, "available", timeout_s=180)

    code, message = _error_detail(
        lambda: rds.create_db_cluster_endpoint(
            DBClusterIdentifier=cluster_id,
            DBClusterEndpointIdentifier=endpoint_id,
            EndpointType="ANY",
        )
    )
    assert code == "DBClusterEndpointAlreadyExistsFault", f"unexpected error code {code!r}: {message!r}"
    expected = f"An endpoint with the identifier {endpoint_id} already exists: {existing['Endpoint']}"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: exactly one endpoint object exists under that identifier, not two.
    matches = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
        "DBClusterEndpoints"
    ]
    assert len(matches) == 1, f"expected exactly 1 endpoint named {endpoint_id!r}, got {len(matches)}"

    # Restore: the rejection is tied to the name being in use, not a permanent
    # reservation of it. Delete the endpoint holding the name, confirm it is gone via an
    # independent read, then the identical create call -- same identifier -- succeeds.
    rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
    _wait_endpoint_gone(ctx, endpoint_id, timeout_s=180)

    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=endpoint_id,
        EndpointType="ANY",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    _wait_endpoint_status(ctx, endpoint_id, "available", timeout_s=180)

    # Positive control (same file): a second, genuinely new endpoint identifier still succeeds.
    second_endpoint_id = ctx.unique_name("sim2real-ep2-")
    rds.create_db_cluster_endpoint(
        DBClusterIdentifier=cluster_id,
        DBClusterEndpointIdentifier=second_endpoint_id,
        EndpointType="ANY",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=second_endpoint_id)
    )
    _wait_endpoint_status(ctx, second_endpoint_id, "available", timeout_s=180)


def _error_detail(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError("CreateDBClusterEndpoint with a name in use succeeded; expected a rejection")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_endpoint_status(ctx, endpoint_id, target_status, timeout_s=180, poll_s=10) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        matches = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
            "DBClusterEndpoints"
        ]
        last = matches[0] if matches else None
        if last is not None and last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"endpoint {endpoint_id} never reached {target_status!r}, last observed {last!r}"
    )


def _wait_endpoint_gone(ctx, endpoint_id, timeout_s=180, poll_s=10) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        matches = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
            "DBClusterEndpoints"
        ]
        if not matches:
            return
        time.sleep(poll_s)
    raise AssertionError(f"endpoint {endpoint_id} was not deleted within {timeout_s}s")


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
