"""update-item-set-to-current-value-still-enforces-condition-expression-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-to-current-value-still-enforces-condition-expression-rejected"
GROUP = "conditions"
SERVICES = ["dynamodb"]
ERR_CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, key):
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


def _code_and_message(fn):
    """The (code, message) *fn* raises; raises AssertionError if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SET that re-assigns an attribute's own current value is still gated by the request's
    ConditionExpression: a failing condition rejects it and leaves the item untouched.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-noop-cond-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "cond"}}
    original = {**key, "val": {"S": "same"}, "cnt": {"N": "1"}}
    ddb.put_item(TableName=table, Item=original)

    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET val = :same",
        ConditionExpression="val = :wrong",
        ExpressionAttributeValues={":same": {"S": "same"}, ":wrong": {"S": "different"}},
    ))
    assert code == ERR_CONDITIONAL_CHECK_FAILED, (
        f"a no-op SET must still be gated by a failing ConditionExpression; expected "
        f"{ERR_CONDITIONAL_CHECK_FAILED}, got {code!r}"
    )
    assert message == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {message!r}"
    )

    unchanged = _get(ddb, table, key)
    assert unchanged == original, (
        f"a rejected no-op SET must not touch the item at all, got {unchanged!r}"
    )

    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET val = :same, #c = :newcnt",
        ConditionExpression="val = :same",
        ExpressionAttributeNames={"#c": "cnt"},
        ExpressionAttributeValues={":same": {"S": "same"}, ":newcnt": {"N": "2"}},
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp["Attributes"]
    assert attrs == {"val": {"S": "same"}, "cnt": {"N": "2"}}, (
        f"a matching condition must let the no-op SET through alongside the real change, and "
        f"UPDATED_NEW must list both, got {attrs!r}"
    )

    final = _get(ddb, table, key)
    assert final == {**key, "val": {"S": "same"}, "cnt": {"N": "2"}}, (
        f"independent GetItem after the accepted update must show the new state, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
