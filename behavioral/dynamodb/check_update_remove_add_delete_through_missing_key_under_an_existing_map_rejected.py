"""update-remove-add-delete-through-missing-key-under-an-existing-map-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-remove-add-delete-through-missing-key-under-an-existing-map-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_PATH_INVALID = (
    "ValidationException",
    "The document path provided in the update expression is invalid for update",
)


def expect_error(fn, code, message):
    """Call fn() and assert the ClientError it raises carries exactly code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return exc
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """REMOVE/ADD/DELETE through a key missing from an existing map reject with the invalid
    document path error and leave the item untouched; REMOVE of that same missing key alone
    (no further traversal) is a no-op, and a real leaf one level deeper still comes off.
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

    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "keep": {"S": "k"},
        "m": {"M": {"a": {"M": {"b": {"S": "x"}}}}},
    }
    ddb.put_item(TableName=table, Item=original)

    # The parent of "child" ("m.absent") does not exist, even though "m" itself does.
    expect_error(
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE m.absent.child"),
        *_PATH_INVALID,
    )
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="ADD m.absent.n :one",
            ExpressionAttributeValues={":one": {"N": "1"}},
        ),
        *_PATH_INVALID,
    )
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="DELETE m.absent.s :v",
            ExpressionAttributeValues={":v": {"SS": ["x"]}},
        ),
        *_PATH_INVALID,
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the three refused updates the item is {unchanged!r}, expected it unchanged "
        f"from {original!r}"
    )

    # REMOVE of "m.absent" itself (the leaf, with no further traversal past it) is a documented
    # no-op: the path's only missing component is the final one, so there is nothing to validate
    # past it.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE m.absent")
    after_noop = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_noop == original, (
        f"REMOVE m.absent (a missing leaf under an existing map) must be a no-op, got "
        f"{after_noop!r}, expected {original!r}"
    )

    # Positive control: the real leaf one level deeper than the probed path still removes.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE m.a.b")
    after_remove = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_remove["m"] == {"M": {"a": {"M": {}}}}, (
        f"REMOVE m.a.b on a real leaf left {after_remove['m']!r}, expected m.a to be an empty map"
    )
    assert after_remove["keep"] == {"S": "k"}, (
        f"the sibling attribute must still read its original value: {after_remove!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
