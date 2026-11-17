"""condition-expression-gt-begins-with-in-as-put-item-condition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-expression-gt-begins-with-in-as-put-item-condition"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")
_NEW = {"S": "put-landed"}

# (case_name, stored attr value, ConditionExpression, ExpressionAttributeValues, expect the write to land)
CASES = [
    ("gt_true", {"N": "20"}, "val > :threshold", {":threshold": {"N": "10"}}, True),
    ("gt_false", {"N": "5"}, "val > :threshold", {":threshold": {"N": "10"}}, False),
    ("begins_with_true", {"S": "hello-world"}, "begins_with(val, :prefix)",
     {":prefix": {"S": "hello"}}, True),
    ("begins_with_false", {"S": "hello-world"}, "begins_with(val, :prefix)",
     {":prefix": {"S": "xyz"}}, False),
    ("in_true", {"S": "b"}, "val IN (:a, :b, :c)",
     {":a": {"S": "a"}, ":b": {"S": "b"}, ":c": {"S": "c"}}, True),
    ("in_false", {"S": "z"}, "val IN (:a, :b, :c)",
     {":a": {"S": "a"}, ":b": {"S": "b"}, ":c": {"S": "c"}}, False),
]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the conditional PutItem to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConditionExpression >, begins_with and IN gate PutItem: a true condition lets the item
    overwrite land, and a false one gives ConditionalCheckFailedException and leaves it unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(TableName=table, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                      AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                      BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    def _stored(pk):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    def _try_conditional_put(pk, condition, values):
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": pk}, "val": _NEW, "marker": {"S": "applied"}},
            ConditionExpression=condition,
            ExpressionAttributeValues=values,
        )

    for case_name, stored, condition, values, expect_pass in CASES:
        pk = case_name
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": stored})

        if expect_pass:
            _try_conditional_put(pk, condition, values)
            got = _stored(pk)
            assert got == {"pk": {"S": pk}, "val": _NEW, "marker": {"S": "applied"}}, (
                f"{case_name}: a passing conditional PutItem did not land: {got!r}")
        else:
            expect_error(lambda pk=pk, condition=condition, values=values:
                         _try_conditional_put(pk, condition, values), *_CCFE)
            got = _stored(pk)
            assert got == {"pk": {"S": pk}, "val": stored}, (
                f"{case_name}: a rejected conditional PutItem must leave the item unchanged, got {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
