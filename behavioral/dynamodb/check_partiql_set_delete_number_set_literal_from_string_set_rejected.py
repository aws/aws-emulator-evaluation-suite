"""partiql-set-delete-number-set-literal-from-string-set-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-set-delete-number-set-literal-from-string-set-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_OPERAND_TYPE = (
    "ValidationException",
    "An operand in the update expression has an incorrect data type",
)


def _wait_table_active(ctx, ddb, table_name):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's remaining time."""
    left = ctx.time_left()
    budget_s = 90.0 if left is None else max(5.0, min(90.0, left - 10.0))
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]
        if last["TableStatus"] == "ACTIVE":
            return last
        time.sleep(1.0)
    raise AssertionError(f"table {table_name} never went ACTIVE in {budget_s}s: {last!r}")


def expect_error(fn, code, message):
    """Call fn() and assert the ClientError it raises carries exactly (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement refuses set_delete of a Number Set literal from a String Set attribute
    with the operand-type ValidationException, and leaves the set unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    _wait_table_active(ctx, ddb, t)

    key = {"pk": {"S": "s1"}}
    ddb.put_item(TableName=t, Item={**key, "tags": {"SS": ["a", "b"]}})

    def _stored():
        return ddb.get_item(TableName=t, Key=key, ConsistentRead=True)["Item"]

    # Negative: set_delete(tags, <<5>>) deletes a Number Set literal from a String Set attribute,
    # refused for the operand type mismatch.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{t}\" SET tags = set_delete(tags, <<5>>) WHERE pk = ?",
            Parameters=[{"S": "s1"}],
        ),
        *_OPERAND_TYPE,
    )
    item = _stored()
    assert set(item["tags"]["SS"]) == {"a", "b"}, (
        f"the refused set_delete must leave tags unchanged, got {item.get('tags')!r}"
    )

    # Positive control: set_delete of a same-typed (String Set) member succeeds.
    ddb.execute_statement(
        Statement=f"UPDATE \"{t}\" SET tags = set_delete(tags, <<'a'>>) WHERE pk = ?",
        Parameters=[{"S": "s1"}],
    )
    item = _stored()
    assert set(item["tags"]["SS"]) == {"b"}, (
        f"the positive control's same-typed set_delete must leave {{'b'}}, got {item.get('tags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
