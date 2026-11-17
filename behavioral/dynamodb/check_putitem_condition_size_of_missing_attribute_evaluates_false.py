"""putitem-condition-size-of-missing-attribute-evaluates-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-size-of-missing-attribute-evaluates-false"
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression of 'size(note) = :zero' against an item that never carries
    'note' evaluates false (ConditionalCheckFailedException); once 'note' is the empty string,
    the same condition is true.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-sizemiss-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # The item exists but never carries "note": it is missing, not an empty string.
    key = {"pk": {"S": "target"}}
    ddb.put_item(TableName=table, Item=key)
    zero = {":zero": {"N": "0"}}

    # Negative: size() of a missing attribute is undefined, so '= 0' is false and the write
    # that would set "note" under that condition is refused.
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**key, "note": {"S": "first"}},
            ConditionExpression="size(note) = :zero",
            ExpressionAttributeValues=zero,
        ),
        *_CCF,
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert unchanged == key, (
        f"PutItem rejected under 'size(note) = :zero' on a missing attribute must leave the item "
        f"unchanged, got {unchanged!r}"
    )

    # Positive control: once "note" is the empty string (size 0, present), the identical
    # condition is true and the write applies.
    with_empty_note = {**key, "note": {"S": ""}}
    ddb.put_item(TableName=table, Item=with_empty_note)
    second = {**key, "note": {"S": ""}, "mark": {"S": "second"}}
    ddb.put_item(
        TableName=table, Item=second,
        ConditionExpression="size(note) = :zero",
        ExpressionAttributeValues=zero,
    )
    landed = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert landed == second, (
        f"PutItem under 'size(note) = :zero' with note already the empty string must apply, "
        f"got {landed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
