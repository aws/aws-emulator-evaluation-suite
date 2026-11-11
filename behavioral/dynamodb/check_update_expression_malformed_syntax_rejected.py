"""update-expression-malformed-syntax-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-expression-malformed-syntax-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not
    turn into an ordinary error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this UpdateExpression, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateExpression with unparsable grammar (a dangling operator or redundant
    parentheses) is rejected with ValidationException before any mutation occurs, while
    parenthesised arithmetic and a plain assignment on the same item still succeed."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ue-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "item-1"}}
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-1"}, "foo": {"S": "original"}})

    err = _error(
        lambda: ddb.update_item(
            TableName=table_name,
            Key=key,
            UpdateExpression="SET foo =",
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected = '1 validation error detected: Invalid UpdateExpression: Syntax error; token: "<EOF>", near: "="'
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Effect absent: the item's attribute was not touched by the rejected call.
    item = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)["Item"]
    assert item["foo"]["S"] == "original", f"expected 'original' (untouched), got {item['foo']['S']!r}"

    # Positive control: a syntactically valid UpdateExpression on the same item succeeds.
    ddb.update_item(
        TableName=table_name,
        Key=key,
        UpdateExpression="SET foo = :v",
        ExpressionAttributeValues={":v": {"S": "updated"}},
    )
    item = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)["Item"]
    assert item["foo"]["S"] == "updated", f"expected 'updated', got {item['foo']['S']!r}"

    # Parenthesised arithmetic is accepted: parentheses may group an operand pair.
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-1"}, "n": {"N": "5"}})
    ddb.update_item(
        TableName=table_name,
        Key=key,
        UpdateExpression="SET n = (:a + :b)",
        ExpressionAttributeValues={":a": {"N": "1"}, ":b": {"N": "2"}},
    )
    item = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)["Item"]
    assert item["n"]["N"] == "3", f"expected '3' from (:a + :b), got {item['n']['N']!r}"

    # Redundant (doubled) parentheses around a single operand are rejected, before any mutation.
    err = _error(
        lambda: ddb.update_item(
            TableName=table_name,
            Key=key,
            UpdateExpression="SET n = ((:v))",
            ExpressionAttributeValues={":v": {"N": "99"}},
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected_redundant = "1 validation error detected: Invalid UpdateExpression: The expression has redundant parentheses;"
    assert err["Message"] == expected_redundant, (
        f"expected message {expected_redundant!r}, got {err['Message']!r}"
    )
    item = ddb.get_item(TableName=table_name, Key=key, ConsistentRead=True)["Item"]
    assert item["n"]["N"] == "3", f"expected '3' (untouched by the rejected call), got {item['n']['N']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
