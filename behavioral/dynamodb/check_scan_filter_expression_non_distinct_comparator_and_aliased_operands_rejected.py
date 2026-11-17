"""scan-filter-expression-non-distinct-comparator-and-aliased-operands-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-expression-non-distinct-comparator-and-aliased-operands-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_NOT_DISTINCT_NE_QTY = (
    "ValidationException",
    "Invalid FilterExpression: The first operand must be distinct from the remaining operands "
    "for this operator or function; operator: <>, first operand: [qty]",
)
_NOT_DISTINCT_GT_QTY = (
    "ValidationException",
    "Invalid FilterExpression: The first operand must be distinct from the remaining operands "
    "for this operator or function; operator: >, first operand: [qty]",
)


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression naming the same attribute as both operands of <> or > is
    refused at parse time, whether parenthesized under OR/AND or written through an
    alias; a FilterExpression comparing distinct operands still evaluates.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbfnd-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "item1"}, "qty": {"N": "5"}, "category": {"S": "A"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "item2"}, "qty": {"N": "10"}, "category": {"S": "B"}})

    expect_error(
        lambda: ddb.scan(TableName=table, ConsistentRead=True, FilterExpression="qty <> qty"),
        *_NOT_DISTINCT_NE_QTY,
    )
    expect_error(
        lambda: ddb.scan(TableName=table, ConsistentRead=True, FilterExpression="qty > qty"),
        *_NOT_DISTINCT_GT_QTY,
    )
    # Parenthesizing the non-distinct branch and combining it with a well-formed OR branch
    # does not shield it: the parser rejects it before either branch is evaluated.
    expect_error(
        lambda: ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression="(category = :c) OR (qty > qty)",
            ExpressionAttributeValues={":c": {"S": "A"}},
        ),
        *_NOT_DISTINCT_GT_QTY,
    )
    # The alias resolves to its attribute name in the message, not the placeholder.
    expect_error(
        lambda: ddb.scan(
            TableName=table, ConsistentRead=True, FilterExpression="#q <> #q",
            ExpressionAttributeNames={"#q": "qty"},
        ),
        *_NOT_DISTINCT_NE_QTY,
    )

    control_gt = ddb.scan(
        TableName=table, ConsistentRead=True, FilterExpression="qty > :v",
        ExpressionAttributeValues={":v": {"N": "7"}},
    )
    assert control_gt["Count"] == 1, f"expected 1 item with qty>7, got {control_gt['Count']}"
    assert control_gt["Items"][0]["pk"] == {"S": "item2"}, (
        f"expected item2 to match qty>7, got {control_gt['Items'][0].get('pk')!r}"
    )

    control_eq = ddb.scan(
        TableName=table, ConsistentRead=True, FilterExpression="category = :c",
        ExpressionAttributeValues={":c": {"S": "A"}},
    )
    assert control_eq["Count"] == 1, f"expected 1 item with category=A, got {control_eq['Count']}"
    assert control_eq["Items"][0]["pk"] == {"S": "item1"}, (
        f"expected item1 to match category=A, got {control_eq['Items'][0].get('pk')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
