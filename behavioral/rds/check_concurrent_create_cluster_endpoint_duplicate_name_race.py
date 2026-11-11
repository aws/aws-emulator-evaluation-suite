"""concurrent-create-cluster-endpoint-duplicate-name-race."""
from __future__ import annotations

import secrets
import string
import threading
import time

from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-cluster-endpoint-duplicate-name-race"
GROUP = "concurrency"
SERVICES = ["rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-eprace"},
    {"Key": "sim2real", "Value": "concurrent-create-cluster-endpoint-duplicate-name-race"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous CreateDBClusterEndpoint calls with the same identifier yield exactly one
    success and one DBClusterEndpointAlreadyExistsFault, and only one endpoint object exists."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-eprace-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    endpoint_id = ctx.unique_name("sim2real-ep-")

    def _create():
        return rds.create_db_cluster_endpoint(
            DBClusterIdentifier=cluster_id,
            DBClusterEndpointIdentifier=endpoint_id,
            EndpointType="ANY",
            Tags=_TAGS,
        )["DBClusterEndpointIdentifier"]

    ctx.on_cleanup(lambda: _delete_endpoint_ignore_missing(rds, endpoint_id))

    result_a, result_b = _race_two(_create, _create)
    outcomes = [result_a, result_b]
    successes = [r for r in outcomes if r["ok"]]
    failures = [r for r in outcomes if not r["ok"]]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {outcomes!r}"
    assert len(failures) == 1, f"expected exactly 1 failure, got {len(failures)}: {outcomes!r}"
    assert failures[0]["code"] == "DBClusterEndpointAlreadyExistsFault", (
        f"unexpected error code {failures[0]['code']!r}"
    )

    matches = rds.describe_db_cluster_endpoints(DBClusterEndpointIdentifier=endpoint_id)[
        "DBClusterEndpoints"
    ]
    assert len(matches) == 1, f"expected exactly 1 endpoint object, got {len(matches)}"
    expected = f"An endpoint with the identifier {endpoint_id} already exists: {matches[0]['Endpoint']}"
    assert failures[0]["message"] == expected, failures[0]["message"]


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _delete_endpoint_ignore_missing(rds, endpoint_id) -> None:
    try:
        rds.delete_db_cluster_endpoint(DBClusterEndpointIdentifier=endpoint_id)
    except rds.exceptions.DBClusterEndpointNotFoundFault:
        pass


def _race_two(fn_a, fn_b) -> tuple[dict, dict]:
    barrier = threading.Barrier(2)

    def _wrap(fn):
        def _inner():
            barrier.wait()
            try:
                return {"ok": True, "value": fn(), "code": None}
            except Exception as exc:  # noqa: BLE001 - classify below
                response = getattr(exc, "response", None)
                if response is not None:
                    return {
                        "ok": False,
                        "value": None,
                        "code": response.get("Error", {}).get("Code"),
                        "message": response.get("Error", {}).get("Message"),
                    }
                raise

        return _inner

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_wrap(fn_a))
        fut_b = pool.submit(_wrap(fn_b))
        return fut_a.result(), fut_b.result()


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=15) -> dict:
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
