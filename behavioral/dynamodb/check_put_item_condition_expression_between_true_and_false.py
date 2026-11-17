"""put-item-condition-expression-between-true-and-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-condition-expression-between-true-and-false"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


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


def _item(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression `v BETWEEN :lo AND :hi` that holds lets the write land, and
    one that does not holds the item unchanged with ConditionalCheckFailedException.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbcebtw-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    in_range = {"pk": {"S": "in-range"}, "v": {"N": "5"}}
    out_range = {"pk": {"S": "out-range"}, "v": {"N": "11"}}
    ddb.put_item(TableName=table, Item=in_range)
    ddb.put_item(TableName=table, Item=out_range)

    def put(item, marker):
        return ddb.put_item(
            TableName=table,
            Item={"pk": item["pk"], "v": item["v"], "marker": {"S": marker}},
            ConditionExpression="v BETWEEN :lo AND :hi",
            ExpressionAttributeValues={":lo": {"N": "1"}, ":hi": {"N": "10"}},
        )

    # BETWEEN holds (5 is within [1, 10]): the write lands.
    put(in_range, "landed")
    got = _item(ddb, table, "in-range")
    assert got == {"pk": {"S": "in-range"}, "v": {"N": "5"}, "marker": {"S": "landed"}}, (
        f"PutItem under a holding 'v BETWEEN 1 AND 10' (v = 5) did not land: {got!r}"
    )

    # BETWEEN fails (11 is outside [1, 10]): ConditionalCheckFailedException, item unchanged.
    expect_error(lambda: put(out_range, "should-not-land"), *_CCFE)
    got = _item(ddb, table, "out-range")
    assert got == out_range, (
        f"PutItem refused under 'v BETWEEN 1 AND 10' (v = 11) must leave the item unchanged, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
