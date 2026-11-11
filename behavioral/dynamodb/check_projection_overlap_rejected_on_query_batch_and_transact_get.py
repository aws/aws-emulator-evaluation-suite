"""projection-overlap-rejected-on-query-batch-and-transact-get."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "projection-overlap-rejected-on-query-batch-and-transact-get"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_OVERLAP_A_AB = (
    "Invalid ProjectionExpression: Two document paths overlap with each other; "
    "must remove or rewrite one of these paths; path one: [a], path two: [a, b]"
)
_UNUSED_NAME_Z = "Value provided in ExpressionAttributeNames unused in expressions: keys: {#z}"


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ProjectionExpression 'a, a.b' is refused with the same overlap message on Query, BatchGetItem
    and TransactGetItems, and the overlap is reported ahead of an unused ExpressionAttributeNames key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ProjectionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-projovl-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    item = {"pk": {"S": "k1"}, "a": {"M": {"b": {"S": "vb"}, "c": {"S": "vc"}}}, "x": {"S": "vx"}}
    ddb.put_item(TableName=table, Item=item)
    key = {"pk": {"S": "k1"}}
    want = {"a": {"M": {"b": {"S": "vb"}}}, "x": {"S": "vx"}}

    def query(expr, **extra):
        return ddb.query(
            TableName=table, KeyConditionExpression="pk = :p",
            ExpressionAttributeValues={":p": {"S": "k1"}}, ConsistentRead=True,
            ProjectionExpression=expr, **extra,
        )

    def batch_get(expr):
        return ddb.batch_get_item(RequestItems={
            table: {"Keys": [key], "ProjectionExpression": expr, "ConsistentRead": True},
        })

    def transact_get(expr):
        return ddb.transact_get_items(TransactItems=[
            {"Get": {"TableName": table, "Key": key, "ProjectionExpression": expr}},
        ])

    # Positive controls: a non-overlapping projection is served by each operation.
    got = query("a.b, x")["Items"]
    assert got == [want], f"Query 'a.b, x' returned {got!r}"
    got = batch_get("a.b, x")["Responses"].get(table)
    assert got == [want], f"BatchGetItem 'a.b, x' returned {got!r}"
    got = transact_get("a.b, x")["Responses"]
    assert got == [{"Item": want}], f"TransactGetItems 'a.b, x' returned {got!r}"

    for label, fn in (
        ("Query", lambda: query("a, a.b")),
        ("BatchGetItem", lambda: batch_get("a, a.b")),
        ("TransactGetItems", lambda: transact_get("a, a.b")),
    ):
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", _OVERLAP_A_AB), (
            f"{label} ProjectionExpression 'a, a.b' gave {code!r}: {msg!r}"
        )

    # The unused name alone is refused, so the next arm decides precedence between two defects.
    code, msg = _error(lambda: ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True, ProjectionExpression="a.b, x",
        ExpressionAttributeNames={"#z": "zzz"},
    ))
    assert (code, msg) == ("ValidationException", _UNUSED_NAME_Z), (
        f"GetItem with only an unused name #z gave {code!r}: {msg!r}"
    )

    code, msg = _error(lambda: ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True, ProjectionExpression="a, a.b",
        ExpressionAttributeNames={"#z": "zzz"},
    ))
    assert (code, msg) == ("ValidationException", _OVERLAP_A_AB), (
        f"GetItem with an overlap and an unused name #z gave {code!r}: {msg!r}"
    )
    code, msg = _error(lambda: query("a, a.b", ExpressionAttributeNames={"#z": "zzz"}))
    assert (code, msg) == ("ValidationException", _OVERLAP_A_AB), (
        f"Query with an overlap and an unused name #z gave {code!r}: {msg!r}"
    )

    full = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert full == item, f"the item changed across the refused reads: {full!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
