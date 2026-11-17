"""update-item-attribute-exists-and-comparison-condition-on-absent-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-attribute-exists-and-comparison-condition-on-absent-key"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _expect_error(fn, code, message):
    """Call fn() and grade the exact (code, message) it raises; a success is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"].get("Code")
        got_message = exc.response["Error"].get("Message")
        assert got_code == code, f"expected {code!r}, got {got_code!r}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


def _wait_table_active(ddb, table, timeout_s=60.0) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}")
        time.sleep(1.0)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standalone UpdateItem whose ConditionExpression ANDs attribute_exists(pk) with an
    attribute-value comparison fails with ConditionalCheckFailedException on an absent key and
    creates no item; the same call succeeds once the item and the compared attribute both exist.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_table_active(ddb, table)

    absent_key = {"pk": {"S": "absent-order"}}

    def restock():
        return ddb.update_item(
            TableName=table,
            Key=absent_key,
            UpdateExpression="SET stock = :s",
            ConditionExpression="attribute_exists(pk) AND #st = :want",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":s": {"N": "5"}, ":want": {"S": "open"}},
        )

    _expect_error(restock, *_CCF)

    ghost = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item")
    assert ghost is None, f"the rejected update must create no ghost item, got {ghost!r}"

    # Positive control: create the item with a matching status, then the identical call commits.
    ddb.put_item(TableName=table, Item={**absent_key, "status": {"S": "open"}})
    restock()
    after = ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item")
    assert after == {**absent_key, "status": {"S": "open"}, "stock": {"N": "5"}}, (
        f"expected the restored conditional update to land, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
