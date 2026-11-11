"""transact-write-expression-parse-errors-rejected-top-level."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-expression-parse-errors-rejected-top-level"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_UPDATE_RESERVED = "Invalid UpdateExpression: Attribute name is a reserved keyword; reserved keyword: status"
_CONDITION_RESERVED = (
    "Invalid ConditionExpression: Attribute name is a reserved keyword; reserved keyword: status"
)
_UPDATE_SYNTAX = 'Invalid UpdateExpression: Syntax error; token: "<EOF>", near: "="'
_CONDITION_REDUNDANT_PARENS = "Invalid ConditionExpression: The expression has redundant parentheses;"


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


def _create_table(ctx, ddb, prefix, range_type=None):
    """Create an on-demand table keyed pk (S), plus sk of range_type when given; wait ACTIVE."""
    table = ctx.unique_name(prefix)
    keys = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attrs = [{"AttributeName": "pk", "AttributeType": "S"}]
    if range_type:
        keys.append({"AttributeName": "sk", "KeyType": "RANGE"})
        attrs.append({"AttributeName": "sk", "AttributeType": range_type})
    ddb.create_table(
        TableName=table, KeySchema=keys, AttributeDefinitions=attrs, BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    return table


def _error(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reserved-word, syntax and redundant-parenthesis errors in any TransactWriteItems action are
    a top-level ValidationException without the single-item prefix; nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb, "sim2real-behav-ddb-txpe-")
    seed_key = {"pk": {"S": "seed"}}
    seed = {**seed_key, "status": {"S": "active"}, "foo": {"S": "orig"}}
    ddb.put_item(TableName=table, Item=seed)
    value = {":v": {"S": "active"}}

    defects = {
        "Update reserved word": (
            {"Update": {"TableName": table, "Key": seed_key, "UpdateExpression": "SET status = :v",
                        "ExpressionAttributeValues": value}},
            _UPDATE_RESERVED,
        ),
        "ConditionCheck reserved word": (
            {"ConditionCheck": {"TableName": table, "Key": seed_key,
                                "ConditionExpression": "status = :v", "ExpressionAttributeValues": value}},
            _CONDITION_RESERVED,
        ),
        "Put condition reserved word": (
            {"Put": {"TableName": table, "Item": {"pk": {"S": "put"}}, "ConditionExpression": "status = :v",
                     "ExpressionAttributeValues": value}},
            _CONDITION_RESERVED,
        ),
        "Delete condition reserved word": (
            {"Delete": {"TableName": table, "Key": seed_key, "ConditionExpression": "status = :v",
                        "ExpressionAttributeValues": value}},
            _CONDITION_RESERVED,
        ),
        "Update truncated expression": (
            {"Update": {"TableName": table, "Key": seed_key, "UpdateExpression": "SET foo ="}},
            _UPDATE_SYNTAX,
        ),
        "ConditionCheck redundant parentheses": (
            {"ConditionCheck": {"TableName": table, "Key": seed_key, "ConditionExpression": "((pk = :k))",
                                "ExpressionAttributeValues": {":k": {"S": "seed"}}}},
            _CONDITION_REDUNDANT_PARENS,
        ),
    }
    for i, (label, (action, expected)) in enumerate(defects.items()):
        side_key = {"pk": {"S": f"side-{i}"}}
        side = {"Put": {"TableName": table, "Item": {**side_key, "v": {"S": "1"}}}}
        code, msg, reasons = _error(lambda a=action, s=side: ddb.transact_write_items(TransactItems=[s, a]))
        assert (code, msg) == ("ValidationException", expected), f"{label} gave {code!r}: {msg!r}"
        assert reasons is None, f"{label}: a top-level ValidationException carried {reasons!r}"
        assert _get(ddb, table, side_key) is None, f"{label}: the refused transaction wrote its other Put"
        assert _get(ddb, table, {"pk": {"S": "put"}}) is None, f"{label}: the refused Put landed"
        got = _get(ddb, table, seed_key)
        assert got == seed, f"{label}: the seed item changed to {got!r}"

    ddb.transact_write_items(TransactItems=[
        {"Update": {"TableName": table, "Key": seed_key, "UpdateExpression": "SET #s = :d",
                    "ConditionExpression": "#s = :v", "ExpressionAttributeNames": {"#s": "status"},
                    "ExpressionAttributeValues": {**value, ":d": {"S": "done"}}}},
    ])
    got = _get(ddb, table, seed_key)
    assert got == {**seed, "status": {"S": "done"}}, f"the aliased transactional Update stored {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
