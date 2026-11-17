"""update-item-condition-type-mismatch-and-missing-attribute-evaluate-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-type-mismatch-and-missing-attribute-evaluate-false"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message)."""
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem ConditionExpression evaluates false, never a type error, for begins_with
    against a stored N, for a cross-type N/S equality, and for a comparator on a missing
    attribute; each refuses with ConditionalCheckFailedException and leaves the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-condmismatch-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "fixed-item"}}
    original = {**key, "num": {"N": "42"}, "txt": {"S": "foobar"}}
    ddb.put_item(TableName=table, Item=original)

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]

    # --- begins_with against a stored N attribute, with a correctly-typed S operand ---
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET begins_ok = :u",
            ConditionExpression="begins_with(num, :p)",
            ExpressionAttributeValues={":u": {"BOOL": True}, ":p": {"S": "4"}},
        ),
        *_CCF,
    )
    after = read()
    assert after == original, (
        f"begins_with(num, :p) with num stored as N must leave the item unchanged, got {after!r}"
    )

    # Positive control, same function: begins_with against a correctly-typed S attribute holds.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET begins_ok = :u",
        ConditionExpression="begins_with(txt, :p)",
        ExpressionAttributeValues={":u": {"BOOL": True}, ":p": {"S": "foo"}},
    )
    after_control_1 = read()
    expected_1 = {**original, "begins_ok": {"BOOL": True}}
    assert after_control_1 == expected_1, (
        f"begins_with(txt, :p) over a matching S attribute should have applied the update, "
        f"got {after_control_1!r}, expected {expected_1!r}"
    )

    # --- cross-type equality: num stored as N, operand the same digits as S ---
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET eq_ok = :u",
            ConditionExpression="num = :s",
            ExpressionAttributeValues={":u": {"BOOL": True}, ":s": {"S": "42"}},
        ),
        *_CCF,
    )
    after = read()
    assert after == expected_1, (
        f"num = :s with num (N) and :s (S) holding the same digits must leave the item "
        f"unchanged, got {after!r}"
    )

    # Positive control, same comparator: num = :n with a correctly-typed N operand holds.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET eq_ok = :u",
        ConditionExpression="num = :n",
        ExpressionAttributeValues={":u": {"BOOL": True}, ":n": {"N": "42"}},
    )
    after_control_2 = read()
    expected_2 = {**expected_1, "eq_ok": {"BOOL": True}}
    assert after_control_2 == expected_2, (
        f"num = :n with a correctly-typed N operand should have applied the update, "
        f"got {after_control_2!r}, expected {expected_2!r}"
    )

    # --- comparator on a missing attribute: '>' treats it as absent and is false ---
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET gt_ok = :u",
            ConditionExpression="score > :v",
            ExpressionAttributeValues={":u": {"BOOL": True}, ":v": {"N": "10"}},
        ),
        *_CCF,
    )
    after = read()
    assert after == expected_2, (
        f"'score > :v' against a never-set attribute must leave the item unchanged, got {after!r}"
    )

    # Positive control, same missing attribute: '<>' treats it as not-equal and the write applies.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET gt_ok = :u",
        ConditionExpression="score <> :v",
        ExpressionAttributeValues={":u": {"BOOL": True}, ":v": {"N": "10"}},
    )
    after_control_3 = read()
    expected_3 = {**expected_2, "gt_ok": {"BOOL": True}}
    assert after_control_3 == expected_3, (
        f"'score <> :v' against a missing attribute should have applied the update, "
        f"got {after_control_3!r}, expected {expected_3!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
