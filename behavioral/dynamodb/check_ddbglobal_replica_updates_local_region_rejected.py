"""ddbglobal-replica-updates-local-region-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbglobal-replica-updates-local-region-rejected"
GROUP = "global_tables"
SERVICES = ["dynamodb"]

ERR_VALIDATION = "ValidationException"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """ReplicaUpdates Create and Delete naming the table's own region are refused with
    ValidationException, the refused Delete leaves the table and its item intact, and a legal
    UpdateTable on the same table then succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbglobal-local-")

    # No stream: the local-region refusal precedes global-table preconditions, and enabling the
    # stream later is the positive control.
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table))
    _wait_table_active(ddb, table)

    item = {"pk": {"S": "survivor"},
            "payload": {"S": "must-outlive-both-refusals"},
            "n": {"N": "3"}}
    ddb.put_item(TableName=table, Item=item)

    before = _item(ddb, table, "survivor")
    assert before == item, f"read back {before!r} immediately after the write of {item!r}"

    code, message = _refusal(lambda: ddb.update_table(
        TableName=table, ReplicaUpdates=[{"Create": {"RegionName": ctx.region}}]))
    assert code == ERR_VALIDATION, (
        f"ReplicaUpdates Create naming the table's own region {ctx.region!r} returned {code!r}, "
        f"expected {ERR_VALIDATION!r}; message was {message!r}"
    )
    assert message == "Cannot add or delete the local region through ReplicaUpdates. Use CreateTable, DeleteTable, or UpdateTable as required.", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert "local region" in message, (
        f"the Create form was refused, but not for the local-region reason: {message!r}"
    )

    code, message = _refusal(lambda: ddb.update_table(
        TableName=table, ReplicaUpdates=[{"Delete": {"RegionName": ctx.region}}]))
    assert code == ERR_VALIDATION, (
        f"ReplicaUpdates Delete naming the table's own region {ctx.region!r} returned {code!r}, "
        f"expected {ERR_VALIDATION!r}; message was {message!r}"
    )
    assert message == "Cannot add or delete the local region through ReplicaUpdates. Use CreateTable, DeleteTable, or UpdateTable as required.", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert "local region" in message, (
        f"the Delete form was refused, but not for the local-region reason: {message!r}"
    )

    described = ddb.describe_table(TableName=table)["Table"]
    assert described["TableStatus"] == "ACTIVE", (
        f"table is {described['TableStatus']!r} after a REFUSED ReplicaUpdates Delete of its own "
        f"region -- the refusal must not have started a teardown"
    )
    assert described.get("Replicas", []) == [], (
        f"table reports replicas {described.get('Replicas')!r} after both ReplicaUpdates forms "
        f"were refused"
    )
    listed = [n for n in _all_table_names(ddb) if n == table]
    assert listed == [table], (
        f"ListTables in {ctx.region} reports {listed!r} for this table after the refusals"
    )
    survived = _item(ddb, table, "survivor")
    assert survived == item, (
        f"item is {survived!r} after a REFUSED ReplicaUpdates Delete of the local region; "
        f"expected the untouched {item!r}"
    )

    # Positive control: a legal UpdateTable on the same table succeeds.
    updated = ddb.update_table(
        TableName=table,
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    )["TableDescription"]
    assert updated["StreamSpecification"]["StreamViewType"] == "NEW_AND_OLD_IMAGES", (
        f"UpdateTable accepted the stream change but returned "
        f"{updated.get('StreamSpecification')!r}"
    )
    _wait_table_active(ddb, table)
    after = ddb.describe_table(TableName=table)["Table"]
    assert after.get("StreamSpecification", {}).get("StreamEnabled") is True, (
        f"DescribeTable reports StreamSpecification {after.get('StreamSpecification')!r} after a "
        f"successful UpdateTable that enabled the stream"
    )
    final = _item(ddb, table, "survivor")
    assert final == item, (
        f"item is {final!r} after the legal UpdateTable; expected the untouched {item!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table: str, timeout_s: float = 180) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _item(ddb, table: str, key: str) -> dict | None:
    """GetItem with ConsistentRead, so an eventually consistent read cannot serve a stale item."""
    return ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")


def _refusal(fn: Callable[[], Any]) -> tuple[str, str]:
    """-> (error code, message) for a call AWS must refuse; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _all_table_names(ddb) -> list[str]:
    """Every table name, across all ListTables pages (100 names per page)."""
    names: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        page = ddb.list_tables(**kwargs)
        names.extend(page["TableNames"])
        last = page.get("LastEvaluatedTableName")
        if not last:
            return names
        kwargs = {"ExclusiveStartTableName": last}


def _delete_table_ignore(ddb, table: str) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
