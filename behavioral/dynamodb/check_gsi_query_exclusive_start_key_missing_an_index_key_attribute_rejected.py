"""gsi-query-exclusive-start-key-missing-an-index-key-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-exclusive-start-key-missing-an-index-key-attribute-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]
_INDEX = "StatusIndex"
ERR_VALIDATION = "ValidationException"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, table, timeout_s=180.0) -> None:
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
    raise AssertionError(f"table {table} or its index did not become ACTIVE: {last!r}")


def _error(fn):
    """``(Code, Message)`` for the ``ClientError`` ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query's ExclusiveStartKey missing any one of the table's two key attributes or the
    index's two is rejected with ValidationException, for all four attributes, while a complete
    ExclusiveStartKey continues normally and no rejected call changes the table's contents.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsilekneg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "CustomerId", "KeyType": "HASH"},
                   {"AttributeName": "OrderId", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "CustomerId", "AttributeType": "S"},
            {"AttributeName": "OrderId", "AttributeType": "S"},
            {"AttributeName": "Status", "AttributeType": "S"},
            {"AttributeName": "OrderSeq", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "Status", "KeyType": "HASH"},
                          {"AttributeName": "OrderSeq", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    for i in range(5):
        ddb.put_item(TableName=table, Item={
            "CustomerId": {"S": "cust-01"}, "OrderId": {"S": f"order-{i:03d}"},
            "Status": {"S": "PLACED"}, "OrderSeq": {"N": str(i)},
        })

    def _query(**kw):
        return ddb.query(
            TableName=table, IndexName=_INDEX, KeyConditionExpression="#s = :s",
            ExpressionAttributeNames={"#s": "Status"},
            ExpressionAttributeValues={":s": {"S": "PLACED"}}, **kw,
        )

    # The GSI is eventually consistent: poll until the index holds all five items.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while _query()["Count"] != 5:
        assert time.monotonic() < deadline, "the index never held all five items"
        time.sleep(2)
    page = _query(Limit=1)
    assert [i["OrderId"]["S"] for i in page["Items"]] == ["order-000"], page["Items"]
    real_key = page.get("LastEvaluatedKey")
    assert real_key == {"CustomerId": {"S": "cust-01"}, "OrderId": {"S": "order-000"},
                        "Status": {"S": "PLACED"}, "OrderSeq": {"N": "0"}}, (
        f"expected the first item's four key attributes as the LastEvaluatedKey, got {real_key!r}"
    )

    # Positive control: the real, complete ExclusiveStartKey continues the walk.
    cont = _query(ExclusiveStartKey=real_key)
    cont_ids = [i["OrderId"]["S"] for i in cont["Items"]]
    assert cont_ids == [f"order-{i:03d}" for i in range(1, 5)], (
        f"positive control: the real ExclusiveStartKey must resume after order-000, got {cont_ids!r}"
    )

    for missing in ("CustomerId", "OrderId", "Status", "OrderSeq"):
        bad_key = {k: v for k, v in real_key.items() if k != missing}
        code, message = _error(lambda bad_key=bad_key: _query(ExclusiveStartKey=bad_key))
        assert code == ERR_VALIDATION, (
            f"ExclusiveStartKey missing {missing!r}: expected {ERR_VALIDATION}, got {code}: {message!r}"
        )
        assert message == "The provided starting key is invalid", (
            f"ExclusiveStartKey missing {missing!r}: expected AWS's exact ValidationException "
            f"message, got {message!r}"
        )

    # None of the four rejected calls wrote, deleted or otherwise changed the table.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    final_ids = sorted(i["OrderId"]["S"] for i in final)
    assert final_ids == [f"order-{i:03d}" for i in range(5)], (
        f"expected the original 5 items unchanged after the rejected calls, got {final_ids!r}"
    )

    # A second positive control: the real key still continues the walk after the rejections.
    cont2 = _query(ExclusiveStartKey=real_key)
    assert cont2["Items"] == cont["Items"], (
        f"the real ExclusiveStartKey's continuation changed after the rejected calls: "
        f"{cont2['Items']!r} vs {cont['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
