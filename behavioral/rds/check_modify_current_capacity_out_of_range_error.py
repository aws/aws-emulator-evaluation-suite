"""modify-current-capacity-out-of-range-error."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-current-capacity-out-of-range-error"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster with EngineMode='serverless' on aurora-mysql is rejected with
    InvalidParameterValue and leaves no cluster, while the same Engine/EngineVersion with
    EngineMode='provisioned' becomes available."""
    rds = ctx.client("rds")

    engine_version = _latest_aurora_mysql_engine_version(rds)

    bad_id = ctx.unique_name("sim2real-clus-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    err = _client_error(
        lambda: rds.create_db_cluster(
            DBClusterIdentifier=bad_id,
            Engine="aurora-mysql",
            EngineMode="serverless",
            EngineVersion=engine_version,
            MasterUsername="simadmin",
            MasterUserPassword="Sim2Real!Pwd01",
            DatabaseName="simdb",
            ScalingConfiguration={"MinCapacity": 1, "MaxCapacity": 4, "AutoPause": False},
            Tags=[{"Key": "sim2real", "Value": "true"}],
            DBSubnetGroupName=subnet_group,
        )
    )
    assert err.get("Code") == "InvalidParameterValue", err
    expected = "The engine mode serverless you requested is currently unavailable."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Effect absent: the rejected cluster never came into existence.
    not_found = _client_error(lambda: rds.describe_db_clusters(DBClusterIdentifier=bad_id))
    assert not_found.get("Code") == "DBClusterNotFoundFault", not_found
    expected_nf = f"DBCluster {bad_id} not found."
    assert not_found.get("Message") == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: the identical Engine/EngineVersion with EngineMode='provisioned'
    # still succeeds, proving the account/region is otherwise healthy for aurora-mysql cluster
    # creation and this is not a blanket denial.
    good_id = ctx.unique_name("sim2real-clus-")
    rds.create_db_cluster(
        DBClusterIdentifier=good_id,
        Engine="aurora-mysql",
        EngineMode="provisioned",
        EngineVersion=engine_version,
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real!Pwd01",
        DatabaseName="simdb",
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, good_id))

    # Terminal read is independent of the mutating call: describe_db_clusters (not the create
    # response) must show the provisioned cluster actually became available.
    final_status = _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=good_id)["DBClusters"][0]["Status"],
        lambda s: s == "available",
        timeout_s=900,
    )
    assert final_status == "available", final_status


def _client_error(fn: Callable[[], Any]) -> dict:
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _latest_aurora_mysql_engine_version(rds) -> str:
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    if not versions:
        raise AssertionError("no aurora-mysql engine version is offered in this account/region")
    return sorted(v["EngineVersion"] for v in versions)[-1]


def _safe_delete_cluster(ctx, cluster_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBClusterNotFoundFault", "InvalidDBClusterStateFault"):
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
