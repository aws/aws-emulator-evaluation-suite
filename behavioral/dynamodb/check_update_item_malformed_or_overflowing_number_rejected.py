"""update-item-malformed-or-overflowing-number-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-malformed-or-overflowing-number-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_NOT_NUMERIC_MSG = "1 validation error detected: The parameter cannot be converted to a numeric value: {value}"
_OVERFLOW_MSG = (
    "1 validation error detected: Number overflow. Attempting to store a number with magnitude "
    "larger than supported range"
)
_ARITHMETIC_OVERFLOW_MSG = (
    "Number overflow. Attempting to store a number with magnitude larger than supported range"
)
_MAX_N = "9" * 38 + "E+88"


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem SET of N '12e', an NS holding 'abc' or a 201-digit N, AttributeUpdates N 'not_a_num',
    and SET +/-, ADD whose result exceeds the N range are ValidationException; item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-upd-num-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "row1"}}
    item = {**key, "n": {"N": "5"}}
    ddb.put_item(TableName=table, Item=item)

    def set_bad(value):
        return ddb.update_item(TableName=table, Key=key, UpdateExpression="SET bad = :v",
                               ExpressionAttributeValues={":v": value})

    cases = [
        ("SET bad = :v with N '12e'", _NOT_NUMERIC_MSG.format(value="12e"),
         lambda: set_bad({"N": "12e"})),
        ("SET bad = :v with NS ['1', 'abc']", _NOT_NUMERIC_MSG.format(value="abc"),
         lambda: set_bad({"NS": ["1", "abc"]})),
        ("SET bad = :v with a 201-digit N", _OVERFLOW_MSG,
         lambda: set_bad({"N": "1" + "0" * 200})),
        ("AttributeUpdates PUT of N 'not_a_num'", _NOT_NUMERIC_MSG.format(value="not_a_num"),
         lambda: ddb.update_item(TableName=table, Key=key, AttributeUpdates={
             "bad": {"Value": {"N": "not_a_num"}, "Action": "PUT"}})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"UpdateItem {label} gave {code!r}: {msg!r}"
        got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
        assert got == item, f"refused UpdateItem {label} changed the item to {got!r}"

    big = {"pk": {"S": "big"}, "v": {"N": _MAX_N}}
    neg = {"pk": {"S": "neg"}, "v": {"N": "-" + _MAX_N}}
    ddb.put_item(TableName=table, Item=big)
    ddb.put_item(TableName=table, Item=neg)
    stored = {}
    for row in (big, neg):
        stored[row["pk"]["S"]] = ddb.get_item(TableName=table, Key={"pk": row["pk"]},
                                              ConsistentRead=True)["Item"]
    arithmetic = [
        ("SET v = v + :m on the largest N", big, "SET v = v + :m"),
        ("ADD v :m on the largest N", big, "ADD v :m"),
        ("SET v = v - :m on the most negative N", neg, "SET v = v - :m"),
    ]
    for label, row, expression in arithmetic:
        code, msg = _error(lambda row=row, expression=expression: ddb.update_item(
            TableName=table, Key={"pk": row["pk"]}, UpdateExpression=expression,
            ExpressionAttributeValues={":m": {"N": _MAX_N}}))
        assert (code, msg) == ("ValidationException", _ARITHMETIC_OVERFLOW_MSG), (
            f"UpdateItem {label} gave {code!r}: {msg!r}"
        )
        got = ddb.get_item(TableName=table, Key={"pk": row["pk"]}, ConsistentRead=True).get("Item")
        assert got == stored[row["pk"]["S"]], f"refused UpdateItem {label} changed the item to {got!r}"

    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET good = :v",
                    ExpressionAttributeValues={":v": {"N": "42"}})
    ddb.update_item(TableName=table, Key=key, AttributeUpdates={
        "legacy": {"Value": {"NS": ["1", "2"]}, "Action": "PUT"}})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert got.get("good") == {"N": "42"}, f"UpdateItem SET good = 42 left {got!r}"
    assert sorted(got.get("legacy", {}).get("NS", [])) == ["1", "2"], f"AttributeUpdates NS PUT left {got!r}"
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET n = n + :one ADD c :one",
                    ExpressionAttributeValues={":one": {"N": "1"}})
    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert (got.get("n"), got.get("c")) == ({"N": "6"}, {"N": "1"}), f"in-range arithmetic left {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
