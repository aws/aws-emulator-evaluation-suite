"""query-gsi-two-hash-one-range-key-exclusive-start-key-missing-an-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-gsi-two-hash-one-range-key-exclusive-start-key-missing-an-attribute-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-tenant-region"
_ERR_VALIDATION = "ValidationException"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        indexes = last.get("GlobalSecondaryIndexes", [])
        if last["TableStatus"] == "ACTIVE" and indexes and all(
            g.get("IndexStatus") == "ACTIVE" for g in indexes
        ):
            return
        time.sleep(3)
    raise AssertionError(f"table {table} or its GSI did not become ACTIVE: {last!r}")


def _error(fn):
    """``(Code, Message)`` for the ``ClientError`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _query(ddb, table, **kw):
    return ddb.query(
        TableName=table, IndexName=_INDEX, KeyConditionExpression="tenant = :t AND #r = :r",
        ExpressionAttributeNames={"#r": "region"},
        ExpressionAttributeValues={":t": {"S": "acme"}, ":r": {"S": "eu"}}, **kw,
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query's ExclusiveStartKey missing the table's key attribute or any one of the
    index's two HASH and one RANGE attributes is rejected with ValidationException, and the
    table's contents and a complete key's continuation are unchanged by the rejections."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi2h1rneg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "tenant", "AttributeType": "S"},
            {"AttributeName": "region", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "tenant", "KeyType": "HASH"},
                {"AttributeName": "region", "KeyType": "HASH"},
                {"AttributeName": "ts", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    for i in range(5):
        ddb.put_item(TableName=table, Item={
            "pk": {"S": f"item-{i:03d}"}, "tenant": {"S": "acme"}, "region": {"S": "eu"},
            "ts": {"S": f"{i:03d}"},
        })

    # The GSI is eventually consistent: poll until the index holds all five items.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while _query(ddb, table)["Count"] != 5:
        assert time.monotonic() < deadline, "the index never held all five items"
        time.sleep(2)
    page = _query(ddb, table, Limit=1)
    assert [i["pk"]["S"] for i in page["Items"]] == ["item-000"], page["Items"]
    real_key = page.get("LastEvaluatedKey")
    assert real_key == {"pk": {"S": "item-000"}, "tenant": {"S": "acme"}, "region": {"S": "eu"},
                        "ts": {"S": "000"}}, (
        f"expected the first item's four key attributes as the LastEvaluatedKey, got {real_key!r}"
    )

    # Positive control: the real, complete ExclusiveStartKey continues the walk.
    cont = _query(ddb, table, ExclusiveStartKey=real_key)
    cont_ids = [i["pk"]["S"] for i in cont["Items"]]
    assert cont_ids == [f"item-{i:03d}" for i in range(1, 5)], (
        f"positive control: the real ExclusiveStartKey must resume after item-000, got {cont_ids!r}"
    )

    for missing in ("pk", "tenant", "region", "ts"):
        bad_key = {k: v for k, v in real_key.items() if k != missing}
        code, message = _error(lambda bad_key=bad_key: _query(ddb, table, ExclusiveStartKey=bad_key))
        assert code == _ERR_VALIDATION, (
            f"ExclusiveStartKey missing {missing!r}: expected {_ERR_VALIDATION}, got {code}: {message!r}"
        )
        assert message == "The provided starting key is invalid", (
            f"ExclusiveStartKey missing {missing!r}: expected AWS's exact ValidationException "
            f"message, got {message!r}"
        )

    # None of the four rejected calls wrote, deleted or otherwise changed the table.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    final_ids = sorted(i["pk"]["S"] for i in final)
    assert final_ids == [f"item-{i:03d}" for i in range(5)], (
        f"expected the original 5 items unchanged after the rejected calls, got {final_ids!r}"
    )

    # A second positive control: the real key still continues the walk after the rejections.
    cont2 = _query(ddb, table, ExclusiveStartKey=real_key)
    assert cont2["Items"] == cont["Items"], (
        f"the real ExclusiveStartKey's continuation changed after the rejected calls: "
        f"{cont2['Items']!r} vs {cont['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
