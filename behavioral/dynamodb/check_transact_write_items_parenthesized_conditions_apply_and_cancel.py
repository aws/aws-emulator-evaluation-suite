"""transact-write-items-parenthesized-conditions-apply-and-cancel."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-parenthesized-conditions-apply-and-cancel"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_TXN_CANCELED = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[None, ConditionalCheckFailed]",
)


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
    """Poll DescribeTable every 2 s until the table is ACTIVE against a deadline."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, pk):
    """The item at pk read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


def expect_error(fn, code, message):
    """Assert fn() raises a ClientError with exactly (code, message); re-raise an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parenthesized ConditionExpression in Put, Update, Delete and ConditionCheck evaluates
    like its unparenthesized form; a failing one cancels the whole transaction, unchanged state.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-txpar-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    put_seed = {"pk": {"S": "tw-put"}, "status": {"S": "pending"}, "qty": {"N": "5"}}
    update_seed = {"pk": {"S": "tw-update"}, "status": {"S": "active"}, "qty": {"N": "10"}}
    delete_seed = {"pk": {"S": "tw-delete"}, "status": {"S": "ready"}, "qty": {"N": "0"}}
    check_seed = {"pk": {"S": "tw-check"}, "status": {"S": "checked"}, "qty": {"N": "1"}}
    for item in (put_seed, update_seed, delete_seed, check_seed):
        ddb.put_item(TableName=table, Item=item)

    # Per-condition "(a) AND (b)" on Put, full-wrap "(a AND b)" on Update, nested
    # "(a AND (b))" on Delete, per-condition again on ConditionCheck: each must pass
    # and apply exactly as its unparenthesized form would.
    names = {"#s": "status"}
    ddb.transact_write_items(TransactItems=[
        {"Put": {
            "TableName": table,
            "Item": {"pk": {"S": "tw-put"}, "status": {"S": "done"}, "qty": {"N": "99"}},
            "ConditionExpression": "(#s = :s) AND (qty = :q)",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": {":s": {"S": "pending"}, ":q": {"N": "5"}},
        }},
        {"Update": {
            "TableName": table,
            "Key": {"pk": {"S": "tw-update"}},
            "UpdateExpression": "SET qty = :newq",
            "ConditionExpression": "(#s = :s AND qty = :q)",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": {
                ":s": {"S": "active"}, ":q": {"N": "10"}, ":newq": {"N": "20"},
            },
        }},
        {"Delete": {
            "TableName": table,
            "Key": {"pk": {"S": "tw-delete"}},
            "ConditionExpression": "(#s = :s AND (qty = :q))",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": {":s": {"S": "ready"}, ":q": {"N": "0"}},
        }},
        {"ConditionCheck": {
            "TableName": table,
            "Key": {"pk": {"S": "tw-check"}},
            "ConditionExpression": "(#s = :s) AND (qty = :q)",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": {":s": {"S": "checked"}, ":q": {"N": "1"}},
        }},
    ])

    got_put = _get(ddb, table, "tw-put")
    assert got_put == {"pk": {"S": "tw-put"}, "status": {"S": "done"}, "qty": {"N": "99"}}, (
        f"Put with a per-condition parenthesized ConditionExpression gave {got_put!r}"
    )
    got_update = _get(ddb, table, "tw-update")
    assert got_update == {"pk": {"S": "tw-update"}, "status": {"S": "active"}, "qty": {"N": "20"}}, (
        f"Update with a fully-wrapped parenthesized ConditionExpression gave {got_update!r}"
    )
    got_delete = _get(ddb, table, "tw-delete")
    assert got_delete is None, (
        f"Delete with a nested parenthesized ConditionExpression left {got_delete!r}"
    )
    got_check = _get(ddb, table, "tw-check")
    assert got_check == check_seed, (
        f"ConditionCheck with a per-condition parenthesized ConditionExpression changed the item to {got_check!r}"
    )

    # A failing parenthesized condition (nested form, deliberately wrong qty) cancels the
    # whole transaction: the sibling Put is rolled back and the Update target is unchanged.
    reasons = expect_error(
        lambda: ddb.transact_write_items(TransactItems=[
            {"Put": {
                "TableName": table,
                "Item": {"pk": {"S": "tw-neg-put"}, "status": {"S": "new"}, "qty": {"N": "1"}},
            }},
            {"Update": {
                "TableName": table,
                "Key": {"pk": {"S": "tw-update"}},
                "UpdateExpression": "SET qty = :newq2",
                "ConditionExpression": "(#s = :s2 AND (qty = :qwrong))",
                "ExpressionAttributeNames": {"#s": "status"},
                "ExpressionAttributeValues": {
                    ":s2": {"S": "active"}, ":qwrong": {"N": "999"}, ":newq2": {"N": "30"},
                },
            }},
        ]),
        *_TXN_CANCELED,
    )
    assert reasons == [
        {"Code": "None"},
        {"Code": "ConditionalCheckFailed", "Message": "The conditional request failed"},
    ], f"cancellation reasons were {reasons!r}"
    got_neg_put = _get(ddb, table, "tw-neg-put")
    assert got_neg_put is None, f"the canceled transaction's sibling Put landed: {got_neg_put!r}"
    got_update_after = _get(ddb, table, "tw-update")
    assert got_update_after == got_update, (
        f"tw-update changed to {got_update_after!r} despite the canceled transaction"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
