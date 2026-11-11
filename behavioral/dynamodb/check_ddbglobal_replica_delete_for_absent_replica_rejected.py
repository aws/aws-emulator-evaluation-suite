"""ddbglobal-replica-delete-for-absent-replica-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddbglobal-replica-delete-for-absent-replica-rejected"
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
    """UpdateTable ReplicaUpdates Delete for a region with no replica is a ValidationException
    "replica not found", distinct from the local-region refusal; the table stays ACTIVE and usable.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    region_b = _derived_second_region(ctx)
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbglobal-absent-")

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table))
    _wait_table_active(ddb, table)

    item = {"pk": {"S": "untouched"},
            "payload": {"S": "survives-a-refused-replica-removal"},
            "n": {"N": "5"}}
    ddb.put_item(TableName=table, Item=item)
    before = _item(ddb, table, "untouched")
    assert before == item, f"read back {before!r} immediately after writing {item!r}"

    # ESTABLISH the precondition rather than assuming it: the replica really is absent, so the
    # refusal below is about an absent replica and not about a stale one.
    described = ddb.describe_table(TableName=table)["Table"]
    present = [r["RegionName"] for r in described.get("Replicas", [])]
    assert region_b not in present, (
        f"derived partner region {region_b!r} already holds a replica of this freshly created "
        f"table; DescribeTable reported replicas {present!r}"
    )

    absent_code, absent_message = _refusal_past_cross_region_token(lambda: ddb.update_table(
        TableName=table, ReplicaUpdates=[{"Delete": {"RegionName": region_b}}]))
    assert absent_code == ERR_VALIDATION, (
        f"ReplicaUpdates Delete for the absent replica in {region_b!r} returned {absent_code!r}, "
        f"expected {ERR_VALIDATION!r}; message was {absent_message!r}"
    )
    expected_absent = (
        "Replica specified in the Replica Update or Replica Delete action of the request was "
        "not found."
    )
    assert absent_message == expected_absent, (
        f"the removal was refused with {absent_message!r}, expected {expected_absent!r}"
    )

    # The refusal is REGION-SPECIFIC, not blanket: handed the table's own region instead, the same
    # operation is refused for a different, distinguishable reason. Only the difference is asserted
    # here -- the local-region contract itself is a separate check.
    local_code, local_message = _refusal(lambda: ddb.update_table(
        TableName=table, ReplicaUpdates=[{"Delete": {"RegionName": ctx.region}}]))
    assert local_code == ERR_VALIDATION, (
        f"ReplicaUpdates Delete naming {ctx.region!r} returned {local_code!r}, expected "
        f"{ERR_VALIDATION!r}; message was {local_message!r}"
    )
    expected_local = (
        "Cannot add or delete the local region through ReplicaUpdates. Use CreateTable, "
        "DeleteTable, or UpdateTable as required."
    )
    assert local_message == expected_local, (
        f"ReplicaUpdates Delete naming {ctx.region!r} was refused with {local_message!r}, "
        f"expected {expected_local!r}"
    )
    assert local_message != absent_message, (
        f"ReplicaUpdates Delete gives the SAME message for the table's own region and for a "
        f"region with no replica ({absent_message!r}) -- the region argument is not being resolved"
    )

    # EFFECT ABSENT: the refused removals changed nothing.
    after = ddb.describe_table(TableName=table)["Table"]
    assert after["TableStatus"] == "ACTIVE", (
        f"table is {after['TableStatus']!r} after two REFUSED ReplicaUpdates Delete calls"
    )
    assert after.get("Replicas", []) == [], (
        f"table reports replicas {after.get('Replicas')!r} after two refused removals"
    )
    listed = [n for n in _all_table_names(ddb) if n == table]
    assert listed == [table], (
        f"ListTables in {ctx.region} reports {listed!r} for this table after the refusals"
    )
    survived = _item(ddb, table, "untouched")
    assert survived == item, (
        f"item is {survived!r} after the refused removals; expected the untouched {item!r}"
    )

    # POSITIVE CONTROL: the data plane still accepts and returns new writes after the refusals, so
    # the table was left fully functional rather than merely present.
    fresh = {"pk": {"S": "written-after"},
             "payload": {"S": "table-is-still-writable"},
             "n": {"N": "6"}}
    ddb.put_item(TableName=table, Item=fresh)
    got_fresh = _item(ddb, table, "written-after")
    assert got_fresh == fresh, (
        f"a write issued after the refused removals read back {got_fresh!r}, wrote {fresh!r}"
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
    """ConsistentRead, always: an eventually-consistent GetItem can serve a pre-write view and make
    "the item survived" pass or fail for a reason that is not the refusal under test."""
    return ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")


def _refusal(fn: Callable[[], Any]) -> tuple[str, str]:
    """(error code, message) for a call AWS must refuse; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _refusal_past_cross_region_token(fn: Callable[[], Any], attempts: int = 3,
                                     backoff_s: float = 2.0) -> tuple[str, str]:
    """`_refusal`, retried while DynamoDB's own call to the partner region is refused for its token
    (AccessDeniedException wrapping UnrecognizedClientException), which is transient."""
    for attempt in range(1, attempts):
        code, message = _refusal(fn)
        if not (code == "AccessDeniedException" and "UnrecognizedClientException" in message):
            return code, message
        time.sleep(backoff_s * attempt)
    return _refusal(fn)


def _all_table_names(ddb) -> list[str]:
    """Every table name; ListTables pages at 100 names, so page one alone can miss this table."""
    names: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        page = ddb.list_tables(**kwargs)
        names.extend(page["TableNames"])
        last = page.get("LastEvaluatedTableName")
        if not last:
            return names
        kwargs = {"ExclusiveStartTableName": last}


def _derived_second_region(ctx) -> str:
    """The partner region: us-east-1, or us-west-2 when ctx.region is us-east-1. Both are
    enabled in every account, so choosing one needs no EC2 call and reads no account state."""
    return "us-east-1" if ctx.region != "us-east-1" else "us-west-2"


def _delete_table_ignore(ddb, table: str) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
