"""update-set-through-missing-intermediate-map-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-through-missing-intermediate-map-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_PATH_INVALID = "The document path provided in the update expression is invalid for update"


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SET a.b.c is refused when map a exists but a.b does not, and the item is unchanged; once
    a.b is a map the same SET succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-midpath-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "deep-miss"}}
    seeded = {**key, "a": {"M": {"x": {"S": "y"}}}}
    ddb.put_item(TableName=table, Item=seeded)

    code, msg = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET a.b.c = :v",
        ExpressionAttributeValues={":v": {"S": "deep"}},
    ))
    assert (code, msg) == ("ValidationException", _PATH_INVALID), (
        f"SET a.b.c with a present but a.b absent gave {code!r}: {msg!r}"
    )
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == seeded, f"the refused SET a.b.c changed the item to {item!r}"

    # Positive control: create the intermediate map, then the same SET is legal.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET a.b = :m",
                    ExpressionAttributeValues={":m": {"M": {}}})
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET a.b.c = :v",
                    ExpressionAttributeValues={":v": {"S": "deep"}})
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    want = {**key, "a": {"M": {"x": {"S": "y"}, "b": {"M": {"c": {"S": "deep"}}}}}}
    assert item == want, f"after creating a.b the item is {item!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
