"""update-item-number-set-condition-exact-at-full-precision."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-number-set-condition-exact-at-full-precision"
GROUP = "representation"
SERVICES = ["dynamodb"]
_CONDITIONAL_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number Set equality condition compares at full decimal precision, not as float64:
    an exact-value NS matches, and a value one digit off is ConditionalCheckFailedException.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    pk = ctx.unique_name("item-")
    stored = "100000000000000001"
    # Same float64 as `stored`; a double-based comparison would treat the two as equal.
    off_by_one = "100000000000000002"

    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "ns": {"NS": [stored]}, "v": {"N": "0"}})

    # Positive control: an exact-value NS condition matches and the update applies.
    ddb.update_item(
        TableName=table,
        Key={"pk": {"S": pk}},
        UpdateExpression="SET v = :nv",
        ConditionExpression="ns = :match",
        ExpressionAttributeValues={":nv": {"N": "1"}, ":match": {"NS": [stored]}},
    )
    after_match = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert after_match["v"] == {"N": "1"}, (
        f"an exact-value NS condition must let the update through, got v={after_match['v']!r}"
    )
    assert after_match["ns"] == {"NS": [stored]}, (
        f"the NS attribute must be unchanged by the update, got {after_match['ns']!r}"
    )

    # Negative: an NS one decimal digit off is a different value at full precision, even though
    # both round to the same float64, so the condition must fail and the update must not apply.
    code, message = _error(lambda: ddb.update_item(
        TableName=table,
        Key={"pk": {"S": pk}},
        UpdateExpression="SET v = :nv",
        ConditionExpression="ns = :off",
        ExpressionAttributeValues={":nv": {"N": "2"}, ":off": {"NS": [off_by_one]}},
    ))
    assert (code, message) == _CONDITIONAL_FAILED, (
        f"an NS condition off by one digit at full precision must be {_CONDITIONAL_FAILED}, "
        f"got {(code, message)!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert unchanged["v"] == {"N": "1"}, (
        f"a write rejected by its condition must leave the item unmodified, got v={unchanged['v']!r}"
    )
    assert unchanged["ns"] == {"NS": [stored]}, (
        f"the NS attribute must still read back exactly, got {unchanged['ns']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
