"""update-item-if-not-exists-charge-only-refused-on-existing-target."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-if-not-exists-charge-only-refused-on-existing-target"
GROUP = "limits"
SERVICES = ["dynamodb"]
_ERR_VALIDATION = ("ValidationException", "Item size to update has exceeded the maximum allowed size")
_OVERSIZED_BYTES = 409700


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore (code, message) *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _expect_error(fn, code: str, message: str) -> None:
    got = _code_and_message(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _create_table(ctx, ddb, table: str) -> None:
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem refuses an oversized if_not_exists operand for size even when the target
    attribute already exists and the not-exists branch never fires, with a passing or
    absent ConditionExpression alike.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbinecharge-")
    _create_table(ctx, ddb, table)
    oversized = {"S": "x" * _OVERSIZED_BYTES}

    # Positive control: with a small operand, if_not_exists on an existing attribute is a
    # no-op -- the existing value survives untouched, proving the not-exists branch is not
    # taken when the target already exists.
    ddb.put_item(TableName=table, Item={"pk": {"S": "ctrl-noop"}, "bigattr": {"S": "orig"}, "flag": {"BOOL": True}})
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "ctrl-noop"}},
        UpdateExpression="SET bigattr = if_not_exists(bigattr, :v)",
        ConditionExpression="flag = :true",
        ExpressionAttributeValues={":v": {"S": "small"}, ":true": {"BOOL": True}},
    )
    noop = ddb.get_item(TableName=table, Key={"pk": {"S": "ctrl-noop"}}, ConsistentRead=True)["Item"]
    assert noop["bigattr"]["S"] == "orig", (
        f"if_not_exists on an existing attribute must keep the existing value, got {noop!r}"
    )

    # The target already exists with a small value, so an accepted update would leave the
    # item unchanged -- yet the oversized operand is still refused for size, with a passing
    # ConditionExpression.
    ddb.put_item(TableName=table, Item={"pk": {"S": "cond-pass"}, "bigattr": {"S": "orig"}, "flag": {"BOOL": True}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "cond-pass"}},
        UpdateExpression="SET bigattr = if_not_exists(bigattr, :v)",
        ConditionExpression="flag = :true",
        ExpressionAttributeValues={":v": oversized, ":true": {"BOOL": True}},
    ), *_ERR_VALIDATION)
    after_pass = ddb.get_item(TableName=table, Key={"pk": {"S": "cond-pass"}}, ConsistentRead=True)["Item"]
    assert after_pass["bigattr"]["S"] == "orig", (
        f"a size refusal must leave the existing value untouched, got {after_pass!r}"
    )

    # ...and with no ConditionExpression at all.
    ddb.put_item(TableName=table, Item={"pk": {"S": "cond-absent"}, "bigattr": {"S": "orig"}})
    _expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "cond-absent"}},
        UpdateExpression="SET bigattr = if_not_exists(bigattr, :v)",
        ExpressionAttributeValues={":v": oversized},
    ), *_ERR_VALIDATION)
    after_absent = ddb.get_item(TableName=table, Key={"pk": {"S": "cond-absent"}}, ConsistentRead=True)["Item"]
    assert after_absent["bigattr"]["S"] == "orig", (
        f"a size refusal must leave the existing value untouched, got {after_absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
