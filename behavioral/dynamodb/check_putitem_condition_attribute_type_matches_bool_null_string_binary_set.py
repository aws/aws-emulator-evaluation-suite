"""putitem-condition-attribute-type-matches-bool-null-string-binary-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-attribute-type-matches-bool-null-string-binary-set"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")

# (label, the attribute carrying the type under test, its right type, a different type to
# condition on for the negative control)
_CASES = (
    ("bool", "flag", {"BOOL": True}, "BOOL", "N"),
    ("null", "missing", {"NULL": True}, "NULL", "S"),
    ("str", "name", {"S": "Mary Major"}, "S", "N"),
    ("bset", "codes", {"BS": [b"\x01\x02"]}, "BS", "S"),
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression attribute_type(#n, :t) matches BOOL, NULL, S and BS
    attributes by their stored type: the overwrite applies when :t names that type, and is
    refused with ConditionalCheckFailedException, item unchanged, when :t names a different one.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbcat-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for label, attr_name, attr_value, right_type, wrong_type in _CASES:
        key = {"pk": {"S": f"item-{label}"}}
        initial = {**key, attr_name: attr_value, "seq": {"N": "1"}}
        ddb.put_item(TableName=table, Item=initial)
        names = {"#n": attr_name}

        # The condition is false: the attribute's stored type is `right_type`, not `wrong_type`,
        # so the write is refused and the item is left exactly as it was.
        expect_error(
            lambda t=table, k=key, a=attr_name, v=attr_value, n=names, w=wrong_type: ddb.put_item(
                TableName=t, Item={**k, a: v, "seq": {"N": "2"}},
                ConditionExpression="attribute_type(#n, :t)",
                ExpressionAttributeNames=n, ExpressionAttributeValues={":t": {"S": w}},
            ),
            *_COND_FAILED,
        )
        unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
        assert unchanged == initial, (
            f"PutItem under a failing attribute_type({attr_name!r}, {wrong_type!r}) condition "
            f"left {unchanged!r}, expected {initial!r} unchanged"
        )

        # The condition is true: the attribute's stored type IS `right_type`, so the write
        # replaces the item.
        replacement = {**key, attr_name: attr_value, "seq": {"N": "2"}}
        ddb.put_item(
            TableName=table, Item=replacement,
            ConditionExpression="attribute_type(#n, :t)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":t": {"S": right_type}},
        )
        replaced = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
        assert replaced == replacement, (
            f"PutItem under a holding attribute_type({attr_name!r}, {right_type!r}) condition "
            f"left {replaced!r}, expected {replacement!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
