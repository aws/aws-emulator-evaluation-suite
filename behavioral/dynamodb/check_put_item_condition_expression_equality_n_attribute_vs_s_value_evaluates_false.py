"""put-item-condition-expression-equality-n-attribute-vs-s-value-evaluates-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-expression-equality-n-attribute-vs-s-value-evaluates-false"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the conditional PutItem to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ConditionExpression `=` comparing a stored N attribute with an S value holding the same
    digits is false, so PutItem fails with ConditionalCheckFailedException and the item is
    unchanged; the same comparison against an N value of equal digits succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbeq-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={"pk": {"S": "item"}, "num": {"N": "5"}})

    def put_conditioned(value):
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": "item"}, "num": {"N": "5"}, "marker": {"S": "applied"}},
            ConditionExpression="num = :v",
            ExpressionAttributeValues={":v": value},
        )

    expect_error(lambda: put_conditioned({"S": "5"}), *_CCF)
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == {"pk": {"S": "item"}, "num": {"N": "5"}}, (
        f"a PutItem rejected under num(N) = :v(S) must leave the item unchanged, got {unchanged!r}"
    )

    # Positive control: the same comparator, matched types, lets the write land -- proving the
    # rejection above is about the type mismatch, not the comparator or the attribute name.
    put_conditioned({"N": "5"})
    landed = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert landed == {"pk": {"S": "item"}, "num": {"N": "5"}, "marker": {"S": "applied"}}, (
        f"a PutItem conditioned on num(N) = :v(N) of the same digits must land, got {landed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
