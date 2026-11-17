"""condition-contains-on-string-is-case-sensitive-for-update."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-contains-on-string-is-case-sensitive-for-update"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem ConditionExpression `contains(#n, :v)` on a String compares byte-for-byte:
    a case-mismatched substring is refused with ConditionalCheckFailedException and leaves the
    item unchanged, while the same substring in its stored case holds and the update applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbcc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "target"}}
    initial = {**key, "name": {"S": "Example Corp"}, "stage": {"S": "start"}}
    ddb.put_item(TableName=table, Item=initial)

    names = {"#n": "name", "#s": "stage"}

    # contains("Example Corp", "corp") is false: the stored value holds "Corp", not "corp", and
    # contains() compares case-sensitively, so the condition fails and the item is untouched.
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key,
            UpdateExpression="SET #s = :done",
            ConditionExpression="contains(#n, :v)",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":v": {"S": "corp"}, ":done": {"S": "done"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == initial, (
        f"UpdateItem under a case-mismatched contains() condition left {unchanged!r}, "
        f"expected {initial!r} unchanged"
    )

    # contains("Example Corp", "Corp") is true: same substring, stored case, so the condition
    # holds and the update applies.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET #s = :done",
        ConditionExpression="contains(#n, :v)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "Corp"}, ":done": {"S": "done"}},
    )
    applied = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected = {**key, "name": {"S": "Example Corp"}, "stage": {"S": "done"}}
    assert applied == expected, (
        f"UpdateItem under a case-matched contains() condition left {applied!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
