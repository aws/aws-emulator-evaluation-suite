"""put-item-number-precision-exceeds-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-number-precision-exceeds-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _error(fn):
    """The Error dict of a call that MUST be refused; RAISES if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number value exceeding DynamoDB's 38-digit precision limit is
    rejected by PutItem with a validation error rather than silently
    truncated or stored, while a normal-precision number round-trips fine."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-numprec-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # 39 significant digits: exceeds the 38-digit precision DynamoDB supports for Number.
    oversized_number = "1" * 39
    bad_key = {"pk": {"S": "oversized"}}
    err = _error(
        lambda: ddb.put_item(
            TableName=table_name,
            Item={"pk": {"S": "oversized"}, "num": {"N": oversized_number}},
        )
    )
    assert err.get("Code") == "ValidationException", (
        f"expected ValidationException, got {err.get('Code')!r}"
    )
    expected = "1 validation error detected: Attempting to store more than 38 significant digits in a Number"
    assert err.get("Message") == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )

    # Effect absent: no item was written for the rejected PutItem.
    resp = ddb.get_item(TableName=table_name, Key=bad_key, ConsistentRead=True)
    assert "Item" not in resp, f"rejected PutItem must not create an item, got {resp.get('Item')!r}"

    # Positive control: a normal-precision number is accepted and round-trips correctly.
    good_key = {"pk": {"S": "normal"}}
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "normal"}, "num": {"N": "12345"}})
    resp = ddb.get_item(TableName=table_name, Key=good_key, ConsistentRead=True)
    assert resp["Item"]["num"]["N"] == "12345", (
        f"normal-precision number did not round-trip, got {resp['Item']['num']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
