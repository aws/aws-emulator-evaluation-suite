"""global-table-settings-describe-update-roundtrip."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "global-table-settings-describe-update-roundtrip"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 2019.11.21 global table replica's read capacity, set via UpdateTable ReplicaUpdates
    ProvisionedThroughputOverride at create and on update, is reported back by DescribeTable under
    Replicas[].WarmThroughput.ReadUnitsPerSecond."""
    # The check has a hard 300 s deadline and replica sync to ACTIVE takes minutes, so the two
    # long polls below share one budget measured from this start time.
    start = time.monotonic()
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    global_name = ctx.unique_name("sim2real-behav-gts-")

    ddb.create_table(
        TableName=global_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, global_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    # A replica cannot be added to a PROVISIONED table unless its write capacity is auto-scaled.
    _register_write_capacity_autoscaling(ctx, aas, global_name)

    # 2019.11.21 global tables are created via UpdateTable ReplicaUpdates (CreateGlobalTable is
    # 2017.11.29-only). An explicit read override makes the baseline value deterministic.
    baseline_rcu = 7
    _create_replica_with_retry(ddb, global_name, region2, read_capacity=baseline_rcu)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, global_name, region2))

    # DescribeGlobalTable returns GlobalTableNotFoundException for a 2019.11.21 table, so readiness
    # is read from DescribeTable Replicas[]. The override value appears under WarmThroughput, not
    # under a ProvisionedThroughputOverride key, so the poll waits for both status and value.
    INNER_BUDGET_S = 275.0
    TAIL_RESERVE_S = 40.0
    baseline_poll_budget = max(60.0, INNER_BUDGET_S - (time.monotonic() - start) - TAIL_RESERVE_S)
    described = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2
            and r["ReplicaStatus"] == "ACTIVE"
            and r.get("WarmThroughput", {}).get("ReadUnitsPerSecond") == baseline_rcu
            for r in table.get("Replicas", [])
        ),
        timeout_s=baseline_poll_budget,
        interval_s=10,
    )
    baseline = _replica_for(described, region2)
    assert baseline is not None, f"expected a replica for {region2}, got {described.get('Replicas', [])}"
    assert baseline["WarmThroughput"]["ReadUnitsPerSecond"] == baseline_rcu, (
        f"expected baseline ReadUnitsPerSecond={baseline_rcu}, got {baseline['WarmThroughput']}"
    )

    new_rcu = 9
    ddb.update_table(
        TableName=global_name,
        ReplicaUpdates=[
            {
                "Update": {
                    "RegionName": region2,
                    "ProvisionedThroughputOverride": {"ReadCapacityUnits": new_rcu},
                }
            }
        ],
    )

    updated_poll_budget = max(20.0, INNER_BUDGET_S - (time.monotonic() - start))
    updated = _poll_until(
        lambda: _replica_for(ddb.describe_table(TableName=global_name)["Table"], region2),
        lambda settings: settings is not None
        and settings.get("WarmThroughput", {}).get("ReadUnitsPerSecond") == new_rcu,
        timeout_s=updated_poll_budget,
        interval_s=5,
    )
    assert updated["WarmThroughput"]["ReadUnitsPerSecond"] == new_rcu, (
        f"expected updated ReadUnitsPerSecond={new_rcu}, got {updated['WarmThroughput']}"
    )
    assert updated["RegionName"] == region2, f"expected replica RegionName={region2}, got {updated['RegionName']}"


def _replica_for(table: dict[str, Any], region: str) -> dict[str, Any] | None:
    for replica in table.get("Replicas", []):
        if replica["RegionName"] == region:
            return replica
    return None

def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _register_write_capacity_autoscaling(ctx: Any, aas: Any, table_name: str) -> None:
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=5,
        MaxCapacity=10,
    )
    ctx.on_cleanup(lambda: _safe_deregister_scalable_target(aas, resource_id, dimension))
    policy_name = ctx.unique_name("sim2real-behav-gts-scale-")
    aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "ScaleInCooldown": 60,
            "ScaleOutCooldown": 60,
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "DynamoDBWriteCapacityUtilization"
            },
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_scaling_policy(aas, policy_name, resource_id, dimension))


def _safe_deregister_scalable_target(aas: Any, resource_id: str, dimension: str) -> None:
    try:
        aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _safe_delete_scaling_policy(aas: Any, policy_name: str, resource_id: str, dimension: str) -> None:
    try:
        aas.delete_scaling_policy(
            PolicyName=policy_name,
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dimension,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


def _create_replica_with_retry(
    ddb: Any,
    table_name: str,
    region: str,
    *,
    read_capacity: int | None = None,
    timeout_s: float = 90,
    interval_s: float = 5,
) -> None:
    """Add a replica, retrying the transient "security token" AccessDeniedException that DynamoDB
    returns while cross-region replication setup settles right after the table turns ACTIVE."""
    create_spec: dict[str, Any] = {"RegionName": region}
    if read_capacity is not None:
        create_spec["ProvisionedThroughputOverride"] = {"ReadCapacityUnits": read_capacity}
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": create_spec}])
            return
        except Exception as exc:  # noqa: BLE001
            transient = _error_code_from_exc(exc) == "AccessDeniedException" and "security token" in str(
                exc
            ).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_remove_replica(ddb: Any, global_name: str, region: str) -> None:
    try:
        ddb.update_table(
            TableName=global_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

