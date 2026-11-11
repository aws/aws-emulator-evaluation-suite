"""create-cluster-conflicting-engine-mode-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-conflicting-engine-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASS = "Sim2RealPwd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateDBCluster with EngineMode='serverless' on aurora-postgresql at its default engine
    version is rejected as an invalid combination, not coerced to 'provisioned'."""
    rds = ctx.client("rds")
    bad_id = ctx.unique_name("sim2real-badmode-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    code, message = _error_code(
        lambda: rds.create_db_cluster(
            DBClusterIdentifier=bad_id,
            Engine="aurora-postgresql",
            EngineMode="serverless",
            MasterUsername=_ADMIN_USER,
            MasterUserPassword=_ADMIN_PASS,
            Tags=[{"Key": "sim2real", "Value": "true"}],
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code!r}"
    expected = "The engine mode serverless you requested is currently unavailable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the cluster was never created.
    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=bad_id)
    )
    assert not_found_code == "DBClusterNotFoundFault", (
        f"cluster {bad_id} unexpectedly exists after a rejected create: {not_found_code!r}"
    )
    expected_nf = f"DBCluster {bad_id} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # Positive control: the same Engine with a compatible (default) EngineMode succeeds.
    good_id = ctx.unique_name("sim2real-goodmode-")
    rds.create_db_cluster(
        DBClusterIdentifier=good_id,
        Engine="aurora-postgresql",
        EngineMode="provisioned",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=_ADMIN_PASS,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, good_id))
    _wait_for_cluster_status(rds, good_id, "available", timeout_s=600)


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _describe_cluster(rds: Any, cluster_id: str) -> dict[str, Any]:
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _describe_cluster(rds, cluster_id)
        if cluster["Status"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached status={status!r} in {timeout_s}s")


def _delete_cluster(rds: Any, cluster_id: str) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise


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
