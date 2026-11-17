"""delete-item-condition-expression-non-distinct-operands-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-expression-non-distinct-operands-rejected"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_NOT_DISTINCT_EQ_SCORE = (
    "ValidationException",
    "1 validation error detected: Invalid ConditionExpression: The first operand must be "
    "distinct from the remaining operands for this operator or function; operator: =, "
    "first operand: [score]",
)
_NOT_DISTINCT_EQ_ALIASED = (
    "ValidationException",
    "1 validation error detected: Invalid ConditionExpression: The first operand must be "
    "distinct from the remaining operands for this operator or function; operator: =, "
    "first operand: [x]",
)
_NOT_DISTINCT_EQ_NESTED = (
    "ValidationException",
    "1 validation error detected: Invalid ConditionExpression: The first operand must be "
    "distinct from the remaining operands for this operator or function; operator: =, "
    "first operand: [info, label]",
)
_NOT_DISTINCT_BEGINS_WITH = (
    "ValidationException",
    "1 validation error detected: Invalid ConditionExpression: The first operand must be "
    "distinct from the remaining operands for this operator or function; operator: begins_with, "
    "first operand: [tag]",
)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DeleteItem ConditionExpression naming the same attribute as both operands of = or
    begins_with is refused, through a bare path, a nested path or two aliases
    resolving to one name, leaving the item untouched; a distinct-operand condition deletes it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-ddbdnd-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    key = {"pk": {"S": "item1"}}
    item = {
        "pk": {"S": "item1"},
        "score": {"N": "5"},
        "x": {"S": "hello"},
        "info": {"M": {"label": {"S": "world"}}},
        "tag": {"S": "prefix-value"},
    }
    ddb.put_item(TableName=table, Item=item)

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")

    def delete(cond, names=None, values=None):
        kwargs = {"TableName": table, "Key": key, "ConditionExpression": cond}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        if values:
            kwargs["ExpressionAttributeValues"] = values
        return ddb.delete_item(**kwargs)

    baseline = read()
    assert baseline == item, f"expected the seeded item back, got {baseline!r}"

    expect_error(lambda: delete("score = score"), *_NOT_DISTINCT_EQ_SCORE)
    assert read() == baseline, "item must survive the rejected 'score = score' delete"

    expect_error(
        lambda: delete("#n = #v", names={"#n": "x", "#v": "x"}),
        *_NOT_DISTINCT_EQ_ALIASED,
    )
    assert read() == baseline, "item must survive the rejected '#n = #v' delete"

    expect_error(lambda: delete("info.label = info.label"), *_NOT_DISTINCT_EQ_NESTED)
    assert read() == baseline, "item must survive the rejected 'info.label = info.label' delete"

    expect_error(lambda: delete("begins_with(tag, tag)"), *_NOT_DISTINCT_BEGINS_WITH)
    assert read() == baseline, "item must survive the rejected 'begins_with(tag, tag)' delete"

    # Positive control: an identical DeleteItem conditioned on a distinct value deletes the item.
    delete("score = :v", values={":v": {"N": "5"}})
    assert read() is None, "expected the item to be gone after the 'score = :v' delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
