"""putitem-condition-expression-le-lt-ge-ordering-operators."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-expression-le-lt-ge-ordering-operators"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")

# (label, operator, stored value when the condition holds, threshold for that case,
#  stored value when the condition does not hold, threshold for that case)
_CASES = [
    ("le", "<=", "5", "5", "6", "5"),
    ("lt", "<", "5", "6", "6", "5"),
    ("ge", ">=", "5", "5", "4", "5"),
]


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression using <=, < or >= against a numeric attribute lets the
    write land when the comparison holds, and refuses it with ConditionalCheckFailedException,
    leaving the item unchanged, when it does not.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-ord-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for label, op, true_val, true_threshold, false_val, false_threshold in _CASES:
        true_key = {"pk": {"S": f"{label}-true"}}
        ddb.put_item(TableName=table, Item={**true_key, "val": {"N": true_val}})
        new_item = {**true_key, "val": {"N": true_val}, "applied": {"BOOL": True}}
        ddb.put_item(
            TableName=table, Item=new_item,
            ConditionExpression=f"val {op} :t",
            ExpressionAttributeValues={":t": {"N": true_threshold}},
        )
        landed = ddb.get_item(TableName=table, Key=true_key, ConsistentRead=True).get("Item")
        assert landed == new_item, (
            f"PutItem under 'val {op} :t' ({true_val} {op} {true_threshold}) should land, got {landed!r}"
        )

        false_key = {"pk": {"S": f"{label}-false"}}
        stored = {**false_key, "val": {"N": false_val}}
        ddb.put_item(TableName=table, Item=stored)
        expect_error(
            lambda op=op, false_key=false_key, false_val=false_val, false_threshold=false_threshold: ddb.put_item(
                TableName=table,
                Item={**false_key, "val": {"N": false_val}, "applied": {"BOOL": True}},
                ConditionExpression=f"val {op} :t",
                ExpressionAttributeValues={":t": {"N": false_threshold}},
            ),
            *_CCF,
        )
        unchanged = ddb.get_item(TableName=table, Key=false_key, ConsistentRead=True).get("Item")
        assert unchanged == stored, (
            f"PutItem rejected under 'val {op} :t' ({false_val} {op} {false_threshold}) must leave "
            f"the item unchanged, got {unchanged!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
