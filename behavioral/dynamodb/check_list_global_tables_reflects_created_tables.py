"""list-global-tables-reflects-created-tables."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-global-tables-reflects-created-tables"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGlobalTables lists only 2017.11.29 global tables: a table made global via UpdateTable
    ReplicaUpdates (version 2019.11.21) is absent before and after DescribeTable shows its replica
    in another region ACTIVE."""
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    global_name = ctx.unique_name("sim2real-behav-lgt-")
    ddb.create_table(
        TableName=global_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
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

    before = _list_global_table_names(ddb)
    assert global_name not in before, (
        f"expected {global_name} absent from ListGlobalTables before any replica exists, "
        f"got it present in {before}"
    )

    # Some accounts reject CreateGlobalTable (2017.11.29); UpdateTable ReplicaUpdates works
    # everywhere and DynamoDB creates the remote replica itself.
    _create_replica_with_retry(ddb, global_name, region2)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, global_name, region2))

    # ListGlobalTables never shows this table, so wait on DescribeTable's Replicas instead.
    described = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=10,
    )
    replicas = described.get("Replicas", [])
    assert any(r["RegionName"] == region2 for r in replicas), (
        f"expected an ACTIVE replica in {region2} via DescribeTable, got replicas {replicas}"
    )

    after = _list_global_table_names(ddb)
    assert global_name not in after, (
        f"expected {global_name} absent from ListGlobalTables even with a genuine ACTIVE "
        f"replica in {region2}, got it present in {after}"
    )


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _create_replica_with_retry(
    ddb: Any, table_name: str, region: str, *, timeout_s: float = 90, interval_s: float = 5
) -> None:
    """Add a replica, retrying the transient "security token" AccessDeniedException that a Create
    issued right as the source table reaches ACTIVE can raise while cross-region setup settles."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
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


def _list_global_table_names(ddb: Any) -> list[str]:
    names: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        resp = ddb.list_global_tables(**kwargs)
        names.extend(g["GlobalTableName"] for g in resp.get("GlobalTables", []))
        last = resp.get("LastEvaluatedGlobalTableName")
        if not last:
            return names
        kwargs["ExclusiveStartGlobalTableName"] = last


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

