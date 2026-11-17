"""scan-filter-expression-non-distinct-function-nested-path-operands-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-expression-non-distinct-function-nested-path-operands-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_NOT_DISTINCT_BEGINS_WITH = (
    "ValidationException",
    "Invalid FilterExpression: The first operand must be distinct from the remaining operands "
    "for this operator or function; operator: begins_with, first operand: [info, label]",
)
_NOT_DISTINCT_ATTRIBUTE_TYPE = (
    "ValidationException",
    "Invalid FilterExpression: The first operand must be distinct from the remaining operands "
    "for this operator or function; operator: attribute_type, first operand: [info, label]",
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
    """A Scan FilterExpression naming the same nested document path as both operands of
    begins_with or attribute_type is refused at parse time, through a bare path or an
    alias; either function with a distinct second operand still evaluates.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbfnp-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "item1"}, "info": {"M": {"label": {"S": "hello"}}}},
    )

    expect_error(
        lambda: ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression="begins_with(info.label, info.label)",
        ),
        *_NOT_DISTINCT_BEGINS_WITH,
    )
    expect_error(
        lambda: ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression="attribute_type(info.label, info.label)",
        ),
        *_NOT_DISTINCT_ATTRIBUTE_TYPE,
    )
    # Aliasing both path segments still resolves to the same document path in the message.
    expect_error(
        lambda: ddb.scan(
            TableName=table, ConsistentRead=True,
            FilterExpression="begins_with(#i.#l, #i.#l)",
            ExpressionAttributeNames={"#i": "info", "#l": "label"},
        ),
        *_NOT_DISTINCT_BEGINS_WITH,
    )

    control_begins_with = ddb.scan(
        TableName=table, ConsistentRead=True,
        FilterExpression="begins_with(info.label, :p)",
        ExpressionAttributeValues={":p": {"S": "hel"}},
    )
    assert control_begins_with["Count"] == 1, (
        f"expected 1 item matching begins_with(info.label, 'hel'), got {control_begins_with['Count']}"
    )
    assert control_begins_with["Items"][0]["pk"] == {"S": "item1"}, (
        f"expected item1 to match, got {control_begins_with['Items'][0].get('pk')!r}"
    )

    control_attribute_type = ddb.scan(
        TableName=table, ConsistentRead=True,
        FilterExpression="attribute_type(info.label, :t)",
        ExpressionAttributeValues={":t": {"S": "S"}},
    )
    assert control_attribute_type["Count"] == 1, (
        f"expected 1 item matching attribute_type(info.label, 'S'), got {control_attribute_type['Count']}"
    )
    assert control_attribute_type["Items"][0]["pk"] == {"S": "item1"}, (
        f"expected item1 to match, got {control_attribute_type['Items'][0].get('pk')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
