"""update-item-set-decimal-arithmetic-updated-old-new."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-decimal-arithmetic-updated-old-new"
GROUP = "representation"
SERVICES = ["dynamodb"]


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
    """SET path = path + :decimal returns the exact decimal sum as UPDATED_NEW, and a later
    SET path = path - :decimal returns the pre-image as UPDATED_OLD while storing the exact
    decimal difference.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.UpdateExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-decset-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "dec-set-arith"}}
    ddb.put_item(TableName=table, Item={**key, "bal": {"N": "12.53"}})

    # SET bal = bal + :inc with a fractional decimal operand: UPDATED_NEW carries the exact sum.
    new1 = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET bal = bal + :inc",
        ExpressionAttributeValues={":inc": {"N": "3.33"}}, ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert new1 == {"bal": {"N": "15.86"}}, (
        f"SET bal = bal + :inc with bal=12.53, :inc=3.33 gave UPDATED_NEW {new1!r}, "
        f"expected {{'bal': {{'N': '15.86'}}}}"
    )
    stored1 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored1 == {**key, "bal": {"N": "15.86"}}, (
        f"stored item after the SET addition is {stored1!r}, expected bal=15.86"
    )

    # SET bal = bal - :dec with a fractional decimal operand: UPDATED_OLD is the pre-image.
    old2 = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET bal = bal - :dec",
        ExpressionAttributeValues={":dec": {"N": "1.08"}}, ReturnValues="UPDATED_OLD",
    )["Attributes"]
    assert old2 == {"bal": {"N": "15.86"}}, (
        f"SET bal = bal - :dec with bal=15.86, :dec=1.08 gave UPDATED_OLD {old2!r}, "
        f"expected the pre-image {{'bal': {{'N': '15.86'}}}}"
    )
    stored2 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored2 == {**key, "bal": {"N": "14.78"}}, (
        f"stored item after the SET subtraction is {stored2!r}, expected bal=14.78 (15.86 - 1.08)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
