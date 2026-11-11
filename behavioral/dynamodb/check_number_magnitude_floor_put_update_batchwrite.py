"""number-magnitude-floor-put-update-batchwrite."""
from __future__ import annotations

from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-magnitude-floor-put-update-batchwrite"
GROUP = "representation"
SERVICES = ["dynamodb"]

# Documented N range floor and ceiling:
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
_FLOOR = "1E-130"
_FLOOR_NEG = "-1E-130"
_BELOW_FLOOR = "1E-131"
_BELOW_FLOOR_NEG = "-1E-131"
_CEIL_POS = "9.9999999999999999999999999999999999999E+125"
_CEIL_NEG = "-9.9999999999999999999999999999999999999E+125"

# DynamoDB folds every accepted N into a canonical plain-decimal string with no exponent;
# Decimal's 'f' format produces the identical string for these magnitudes.
_FLOOR_STORED = format(Decimal(_FLOOR), "f")
_FLOOR_NEG_STORED = format(Decimal(_FLOOR_NEG), "f")
_CEIL_POS_STORED = format(Decimal(_CEIL_POS), "f")
_CEIL_NEG_STORED = format(Decimal(_CEIL_NEG), "f")

# PutItem and UpdateItem wrap the message in the "N validation error(s) detected" envelope;
# BatchWriteItem's ValidationException carries the bare message with no envelope.
_UNDERFLOW_ENVELOPE = (
    "1 validation error detected: Number underflow. Attempting to store a number with "
    "magnitude smaller than supported range"
)
_UNDERFLOW_BARE = (
    "Number underflow. Attempting to store a number with magnitude smaller than supported range"
)
_PUT_UNDERFLOW = ("ValidationException", _UNDERFLOW_ENVELOPE)
_UPDATE_UNDERFLOW = ("ValidationException", _UNDERFLOW_ENVELOPE)
_BATCH_UNDERFLOW = ("ValidationException", _UNDERFLOW_BARE)


def expect_error(fn, code, message):
    """(code, message) fn()'s ClientError carries; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == (code, message), (
            f"expected ({code!r}, {message!r}), got ({err.get('Code')!r}, {err.get('Message')!r})"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem, UpdateItem and BatchWriteItem accept N at the documented magnitude floor and
    ceiling and round-trip the canonical stored string; one step past the floor is
    ValidationException (underflow) with no item written, and the envelope differs by operation.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-numfloor-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def get(pk):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- PutItem: floor and negative-floor are accepted and round-trip the canonical string ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "put-floor"}, "v": {"N": _FLOOR}})
    got = get("put-floor")
    assert got["v"] == {"N": _FLOOR_STORED}, (
        f"PutItem {_FLOOR} must store as {_FLOOR_STORED!r}, got {got['v']}"
    )

    ddb.put_item(TableName=table, Item={"pk": {"S": "put-floor-neg"}, "v": {"N": _FLOOR_NEG}})
    got = get("put-floor-neg")
    assert got["v"] == {"N": _FLOOR_NEG_STORED}, (
        f"PutItem {_FLOOR_NEG} must store as {_FLOOR_NEG_STORED!r}, got {got['v']}"
    )

    # --- PutItem: the negative ceiling is accepted and round-trips ---
    ddb.put_item(TableName=table, Item={"pk": {"S": "put-ceil-neg"}, "v": {"N": _CEIL_NEG}})
    got = get("put-ceil-neg")
    assert got["v"] == {"N": _CEIL_NEG_STORED}, (
        f"PutItem {_CEIL_NEG} must store as {_CEIL_NEG_STORED!r}, got {got['v']}"
    )

    # --- PutItem: an NS holding the positive ceiling, negative ceiling, floor and zero stores all four ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "put-ns"},
        "v": {"NS": [_CEIL_POS, _CEIL_NEG, _FLOOR, "0"]},
    })
    got = get("put-ns")
    assert sorted(got["v"]["NS"]) == sorted([_CEIL_POS_STORED, _CEIL_NEG_STORED, _FLOOR_STORED, "0"]), (
        f"NS of ceiling/floor/zero must store all four members, got {got['v']}"
    )

    # --- PutItem: one step past the floor, on either sign, is underflow and writes nothing ---
    expect_error(
        lambda: ddb.put_item(TableName=table, Item={"pk": {"S": "put-under"}, "v": {"N": _BELOW_FLOOR}}),
        *_PUT_UNDERFLOW,
    )
    assert get("put-under") is None, "a rejected PutItem below the floor must not create the item"

    expect_error(
        lambda: ddb.put_item(TableName=table, Item={"pk": {"S": "put-under-neg"}, "v": {"N": _BELOW_FLOOR_NEG}}),
        *_PUT_UNDERFLOW,
    )
    assert get("put-under-neg") is None, "a rejected PutItem below the negative floor must not create the item"

    # --- UpdateItem: SET to the floor is accepted and round-trips ---
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "upd"}},
        UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"N": _FLOOR}},
    )
    got = get("upd")
    assert got["v"] == {"N": _FLOOR_STORED}, (
        f"UpdateItem SET to {_FLOOR} must store as {_FLOOR_STORED!r}, got {got['v']}"
    )

    # --- UpdateItem: SET one step past the floor is underflow and leaves the item unchanged ---
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key={"pk": {"S": "upd"}},
            UpdateExpression="SET v = :v", ExpressionAttributeValues={":v": {"N": _BELOW_FLOOR}},
        ),
        *_UPDATE_UNDERFLOW,
    )
    got = get("upd")
    assert got["v"] == {"N": _FLOOR_STORED}, (
        f"a rejected UpdateItem below the floor must leave the item at {_FLOOR_STORED!r}, got {got['v']}"
    )

    # --- BatchWriteItem: a single PutRequest at the floor is accepted and round-trips ---
    resp = ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {"pk": {"S": "batch-floor"}, "v": {"N": _FLOOR}}}},
    ]})
    assert resp.get("UnprocessedItems") == {}, f"accepted batch left UnprocessedItems {resp.get('UnprocessedItems')}"
    got = get("batch-floor")
    assert got["v"] == {"N": _FLOOR_STORED}, (
        f"BatchWriteItem {_FLOOR} must store as {_FLOOR_STORED!r}, got {got['v']}"
    )

    # --- BatchWriteItem: one step past the floor rejects the whole request, bare message, writes nothing ---
    expect_error(
        lambda: ddb.batch_write_item(RequestItems={table: [
            {"PutRequest": {"Item": {"pk": {"S": "batch-good"}, "v": {"N": "42"}}}},
            {"PutRequest": {"Item": {"pk": {"S": "batch-under"}, "v": {"N": _BELOW_FLOOR}}}},
        ]}),
        *_BATCH_UNDERFLOW,
    )
    assert get("batch-good") is None, "a rejected BatchWriteItem must not write its other, valid item"
    assert get("batch-under") is None, "a rejected BatchWriteItem below the floor must not create the item"

    # Control: PutItem still succeeds after every rejection above.
    ddb.put_item(TableName=table, Item={"pk": {"S": "ctrl"}, "v": {"N": "42"}})
    assert get("ctrl")["v"] == {"N": "42"}, "control write must still succeed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
