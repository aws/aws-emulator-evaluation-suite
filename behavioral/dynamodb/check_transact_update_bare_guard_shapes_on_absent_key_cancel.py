"""transact-update-bare-guard-shapes-on-absent-key-cancel."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-update-bare-guard-shapes-on-absent-key-cancel"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CANCELED_FIRST_FAILS = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[ConditionalCheckFailed, None]",
)


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
        return exc
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


_WAIT_S = 60.0


def _wait_table_active(ddb, table, timeout_s=_WAIT_S) -> None:
    """Poll DescribeTable until the table is ACTIVE; on expiry fail with the last status read."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}")
        time.sleep(1.0)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update on an absent key cancels the whole transaction and creates no
    item, whether its own condition is a bare attribute_exists guarding an ADD, or a plain
    comparison with no attribute_exists at all; a passing sibling action still rolls back."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_table_active(ddb, table)

    # Scenario A: ADD guarded by a bare attribute_exists(id) (no AND, no equality) on an absent key.
    ghost_key = {"id": {"S": "ghost-tally"}}
    sibling_a_key = {"id": {"S": "sibling-tally-a"}}
    sibling_a_seed = {**sibling_a_key, "count": {"N": "10"}}
    ddb.put_item(TableName=table, Item=sibling_a_seed)

    def bump_tally():
        return ddb.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": table, "Key": ghost_key,
                "UpdateExpression": "ADD #c :inc",
                "ConditionExpression": "attribute_exists(id)",
                "ExpressionAttributeNames": {"#c": "count"},
                "ExpressionAttributeValues": {":inc": {"N": "1"}},
            }},
            {"Update": {
                "TableName": table, "Key": sibling_a_key,
                "UpdateExpression": "SET #c = #c + :inc",
                "ConditionExpression": "#c = :expected",
                "ExpressionAttributeNames": {"#c": "count"},
                "ExpressionAttributeValues": {":inc": {"N": "1"}, ":expected": {"N": "10"}},
            }},
        ])

    exc_a = _expect_error(bump_tally, *_CANCELED_FIRST_FAILS)
    reasons_a = [(r.get("Code"), r.get("Message")) for r in exc_a.response.get("CancellationReasons", [])]
    assert reasons_a == [("ConditionalCheckFailed", "The conditional request failed"), ("None", None)], (
        f"expected [ConditionalCheckFailed, None] cancellation reasons, got {reasons_a!r}"
    )

    ghost_got = ddb.get_item(TableName=table, Key=ghost_key, ConsistentRead=True).get("Item")
    assert ghost_got is None, f"the cancelled ADD must not create the ghost item, got {ghost_got!r}"
    sibling_a_got = ddb.get_item(TableName=table, Key=sibling_a_key, ConsistentRead=True).get("Item")
    assert sibling_a_got == sibling_a_seed, (
        f"the sibling Update's own condition held, but it must still be rolled back: got {sibling_a_got!r}"
    )

    # Positive control: create the ghost item for real, then the identical transaction commits both.
    ddb.put_item(TableName=table, Item={**ghost_key, "count": {"N": "5"}})
    bump_tally()
    ghost_after = ddb.get_item(TableName=table, Key=ghost_key, ConsistentRead=True).get("Item")
    assert ghost_after == {**ghost_key, "count": {"N": "6"}}, (
        f"expected the committed transaction to ADD 1 to the ghost tally, got {ghost_after!r}"
    )
    sibling_a_after = ddb.get_item(TableName=table, Key=sibling_a_key, ConsistentRead=True).get("Item")
    assert sibling_a_after == {**sibling_a_key, "count": {"N": "11"}}, (
        f"expected the committed transaction to bump the sibling's count to 11, got {sibling_a_after!r}"
    )

    # Scenario B: a plain comparison condition, with no attribute_exists at all, on an absent key,
    # inside a transaction.
    lonely_key = {"id": {"S": "lonely-widget"}}
    sibling_b_key = {"id": {"S": "sibling-tally-b"}}
    sibling_b_seed = {**sibling_b_key, "stock": {"N": "5"}}
    ddb.put_item(TableName=table, Item=sibling_b_seed)

    def restock():
        return ddb.transact_write_items(TransactItems=[
            {"Update": {
                "TableName": table, "Key": lonely_key,
                "UpdateExpression": "SET stock = :s",
                "ConditionExpression": "stock > :zero",
                "ExpressionAttributeValues": {":s": {"N": "5"}, ":zero": {"N": "0"}},
            }},
            {"Update": {
                "TableName": table, "Key": sibling_b_key,
                "UpdateExpression": "SET stock = stock + :inc",
                "ConditionExpression": "stock = :expected",
                "ExpressionAttributeValues": {":inc": {"N": "1"}, ":expected": {"N": "5"}},
            }},
        ])

    exc_b = _expect_error(restock, *_CANCELED_FIRST_FAILS)
    reasons_b = [(r.get("Code"), r.get("Message")) for r in exc_b.response.get("CancellationReasons", [])]
    assert reasons_b == [("ConditionalCheckFailed", "The conditional request failed"), ("None", None)], (
        f"expected [ConditionalCheckFailed, None] cancellation reasons, got {reasons_b!r}"
    )

    lonely_got = ddb.get_item(TableName=table, Key=lonely_key, ConsistentRead=True).get("Item")
    assert lonely_got is None, f"the cancelled comparison-guarded update must create nothing, got {lonely_got!r}"
    sibling_b_got = ddb.get_item(TableName=table, Key=sibling_b_key, ConsistentRead=True).get("Item")
    assert sibling_b_got == sibling_b_seed, (
        f"the sibling Update's own condition held, but it must still be rolled back: got {sibling_b_got!r}"
    )

    # Positive control: once the key exists with a satisfying value, the identical transaction commits.
    ddb.put_item(TableName=table, Item={**lonely_key, "stock": {"N": "3"}})
    restock()
    lonely_after = ddb.get_item(TableName=table, Key=lonely_key, ConsistentRead=True).get("Item")
    assert lonely_after == {**lonely_key, "stock": {"N": "5"}}, (
        f"expected the committed transaction to set stock to 5, got {lonely_after!r}"
    )
    sibling_b_after = ddb.get_item(TableName=table, Key=sibling_b_key, ConsistentRead=True).get("Item")
    assert sibling_b_after == {**sibling_b_key, "stock": {"N": "6"}}, (
        f"expected the committed transaction to bump the sibling's stock to 6, got {sibling_b_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
