"""scan-filter-expression-redundant-nested-parens-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-expression-redundant-nested-parens-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_REDUNDANT = ("ValidationException", "Invalid FilterExpression: The expression has redundant parentheses;")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _item(row: tuple) -> dict:
    rid, status, category = row
    return {"id": {"S": rid}, "status": {"S": status}, "category": {"S": category}}


_ROWS = (
    ("item-001", "active", "premium"),
    ("item-002", "inactive", "basic"),
)


def _seed(ctx) -> str:
    """A fresh id-keyed table seeded with two records."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbparenrej-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": _item(r)}} for r in _ROWS]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression wrapping a single comparison, or a NOT comparison, in a
    redundant extra pair of parentheses is rejected; a single pair of parens is accepted.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)
    names = {"#c": "category", "#s": "status"}
    values = {":b": {"S": "basic"}, ":a": {"S": "active"}}

    expect_error(
        lambda: ddb.scan(TableName=name, FilterExpression="((#c = :b))",
                         ExpressionAttributeNames={"#c": "category"},
                         ExpressionAttributeValues={":b": {"S": "basic"}}),
        *_REDUNDANT,
    )
    expect_error(
        lambda: ddb.scan(TableName=name, FilterExpression="((NOT #s = :a))",
                         ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":a": {"S": "active"}}),
        *_REDUNDANT,
    )
    expect_error(
        lambda: ddb.scan(TableName=name, FilterExpression="((#s = :a)) AND #c = :b",
                         ExpressionAttributeNames=names, ExpressionAttributeValues=values),
        *_REDUNDANT,
    )

    control = ddb.scan(TableName=name, FilterExpression="(#c = :b)", ConsistentRead=True,
                       ExpressionAttributeNames={"#c": "category"},
                       ExpressionAttributeValues={":b": {"S": "basic"}})
    ids = sorted(i["id"]["S"] for i in control["Items"])
    expected = sorted(r[0] for r in _ROWS if r[2] == "basic")
    assert ids == expected, (
        f"the single-paren control '(#c = :b)' returned {ids!r}, expected {expected!r}: a single "
        f"pair of parens is accepted, only the redundant extra pair is rejected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
