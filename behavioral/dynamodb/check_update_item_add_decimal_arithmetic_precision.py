"""update-item-add-decimal-arithmetic-precision."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-decimal-arithmetic-precision"
GROUP = "representation"
SERVICES = ["dynamodb"]

_BASE38 = "1" * 37 + "0"  # 38 digits, one short of 38 ones
_TARGET38 = "1" * 38  # the 38-significant-digit ADD result


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD on a Number keeps the exact decimal result for a fractional increment and a
    fractional decrement, and accepts an arithmetic result at exactly 38 significant digits.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-decadd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # ADD with a fractional decimal operand keeps the exact decimal sum.
    key_frac = {"pk": {"S": "dec-add-frac"}}
    ddb.put_item(TableName=table, Item={**key_frac, "bal": {"N": "100.53"}})
    r1 = ddb.update_item(
        TableName=table, Key=key_frac, UpdateExpression="ADD bal :inc",
        ExpressionAttributeValues={":inc": {"N": "25.34"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r1 == {**key_frac, "bal": {"N": "125.87"}}, (
        f"ADD bal :inc with bal=100.53, :inc=25.34 returned {r1!r}, expected bal=125.87"
    )

    # ADD with a negative fractional decimal operand decrements by the exact decimal amount.
    r2 = ddb.update_item(
        TableName=table, Key=key_frac, UpdateExpression="ADD bal :dec",
        ExpressionAttributeValues={":dec": {"N": "-50.12"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r2 == {**key_frac, "bal": {"N": "75.75"}}, (
        f"ADD bal :dec with bal=125.87, :dec=-50.12 returned {r2!r}, expected bal=75.75"
    )
    got_frac = ddb.get_item(TableName=table, Key=key_frac, ConsistentRead=True)["Item"]
    assert got_frac == {**key_frac, "bal": {"N": "75.75"}}, (
        f"stored item after both fractional ADDs is {got_frac!r}, expected bal=75.75"
    )

    # ADD whose arithmetic result lands at exactly 38 significant digits is accepted and
    # rendered with every digit intact.
    key_38 = {"pk": {"S": "dec-add-38digits"}}
    ddb.put_item(TableName=table, Item={**key_38, "bal": {"N": _BASE38}})
    r3 = ddb.update_item(
        TableName=table, Key=key_38, UpdateExpression="ADD bal :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="ALL_NEW",
    )["Attributes"]
    assert r3 == {**key_38, "bal": {"N": _TARGET38}}, (
        f"ADD bal :one with bal={_BASE38!r} returned {r3!r}, expected bal={_TARGET38!r} "
        f"({len(_TARGET38)} significant digits)"
    )
    got_38 = ddb.get_item(TableName=table, Key=key_38, ConsistentRead=True)["Item"]
    assert got_38 == {**key_38, "bal": {"N": _TARGET38}}, (
        f"stored item after the 38-significant-digit ADD is {got_38!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
