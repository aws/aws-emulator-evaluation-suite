"""transact-write-condition-non-orderable-literal-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-condition-non-orderable-literal-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_OPERAND_TYPE_MSG = (
    "Invalid ConditionExpression: Incorrect operand type for operator or function; "
    "operator or function: >, operand type: BOOL"
)
_CANCELLED_MSG = (
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[ConditionalCheckFailed]"
)

_BASE = {"pk": {"S": "p1"}, "n": {"N": "5"}, "note": {"S": "orig"}}


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Put, Delete, Update or ConditionCheck whose condition orders against a
    BOOL value is a top-level ValidationException, not a cancellation, and writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-txn-order-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "p1"}}
    ddb.put_item(TableName=table, Item=_BASE)
    bad = {":v": {"BOOL": True}}

    actions = {
        "Put": {"Put": {"TableName": table, "Item": {**_BASE, "note": {"S": "put"}},
                        "ConditionExpression": "n > :v", "ExpressionAttributeValues": bad}},
        "Delete": {"Delete": {"TableName": table, "Key": key,
                              "ConditionExpression": "n > :v", "ExpressionAttributeValues": bad}},
        "Update": {"Update": {"TableName": table, "Key": key, "UpdateExpression": "SET note = :c",
                              "ConditionExpression": "n > :v",
                              "ExpressionAttributeValues": {**bad, ":c": {"S": "update"}}}},
        "ConditionCheck": {"ConditionCheck": {"TableName": table, "Key": key,
                                              "ConditionExpression": "n > :v",
                                              "ExpressionAttributeValues": bad}},
    }
    other = {"Put": {"TableName": table, "Item": {"pk": {"S": "p2"}, "note": {"S": "side"}}}}
    for name, action in actions.items():
        code, msg = _error(lambda action=action: ddb.transact_write_items(TransactItems=[action, other]))
        assert (code, msg) == ("ValidationException", _OPERAND_TYPE_MSG), (
            f"TransactWriteItems {name} with condition 'n > :v' (:v BOOL) gave {code!r}: {msg!r}"
        )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == _BASE, f"item after the refused transactions is {item!r}, expected {_BASE!r}"
    side = ddb.get_item(TableName=table, Key={"pk": {"S": "p2"}}, ConsistentRead=True).get("Item")
    assert side is None, f"the sibling Put of a refused transaction was written: {side!r}"

    code, msg = _error(lambda: ddb.transact_write_items(TransactItems=[{"ConditionCheck": {
        "TableName": table, "Key": key, "ConditionExpression": "n > :v",
        "ExpressionAttributeValues": {":v": {"N": "9"}}}}]))
    assert (code, msg) == ("TransactionCanceledException", _CANCELLED_MSG), (
        f"a well-formed but false transaction condition (5 > 9) gave {code!r}: {msg!r}"
    )

    ddb.transact_write_items(TransactItems=[
        {"Update": {"TableName": table, "Key": key, "UpdateExpression": "SET note = :c",
                    "ConditionExpression": "n > :v",
                    "ExpressionAttributeValues": {":v": {"N": "0"}, ":c": {"S": "update"}}}},
        other,
    ])
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == {**_BASE, "note": {"S": "update"}}, f"the valid transaction left {item!r}"
    side = ddb.get_item(TableName=table, Key={"pk": {"S": "p2"}}, ConsistentRead=True).get("Item")
    assert side == other["Put"]["Item"], f"the valid transaction's sibling Put left {side!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
