"""update-item-size-floor-treats-key-name-and-value-bytes-equally."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-size-floor-treats-key-name-and-value-bytes-equally"
GROUP = "limits"
SERVICES = ["dynamodb"]

_ITEM_TOO_LARGE = ("ValidationException", "Item size to update has exceeded the maximum allowed size")
_CAP = 409600
_FLAT_FLOOR_BYTES = 22
_V_NAME_LEN = 1  # len("v")
_FLAT_CEILING = _CAP - _V_NAME_LEN - _FLAT_FLOOR_BYTES


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected UpdateItem to be rejected, but it succeeded: {result!r}")


def _expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _probe(ddb, table, key: dict, ceiling: int, preexisting_bytes: int) -> None:
    """Seed key, assert a bare ``SET v = :v`` of exactly ``ceiling`` bytes is accepted and one
    byte more is refused, and that the refused write left no trace.
    """
    ddb.put_item(TableName=table, Item=dict(key))
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                     ExpressionAttributeValues={":v": {"S": "x" * ceiling}})
    accepted = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert len(accepted.get("v", {}).get("S", "")) == ceiling, (
        f"a SET of {ceiling} bytes (predicted for {preexisting_bytes} pre-existing bytes) "
        f"did not read back at that length: {accepted.get('v')!r}"
    )

    ddb.put_item(TableName=table, Item=dict(key))  # reset: no "v" attribute on the stored item
    _expect_error(
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                                ExpressionAttributeValues={":v": {"S": "x" * (ceiling + 1)}}),
        *_ITEM_TOO_LARGE,
    )
    refused = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "v" not in refused, f"a refused SET of {ceiling + 1} bytes still created attribute v: {refused!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's size ceiling crosses from the flat 22-byte floor to the per-byte charge
    at the same total key-attribute byte count whether those bytes come from the key's
    name or from the key's value -- not only once both are well past the floor.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")

    # Crossing the floor by KEY VALUE length, key name fixed at 1 byte ("k").
    value_table = ctx.unique_name("sim2real-behav-ddbfloorval-")
    ddb.create_table(
        TableName=value_table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=value_table))
    ddb.get_waiter("table_exists").wait(TableName=value_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    # 1-byte name + 21-byte value = 22 pre-existing bytes: at the floor, still flat.
    _probe(ddb, value_table, {"k": {"S": "v" * 21}}, _FLAT_CEILING, 22)
    # 1-byte name + 22-byte value = 23 pre-existing bytes: one past the floor.
    _probe(ddb, value_table, {"k": {"S": "v" * 22}}, _FLAT_CEILING - 1, 23)

    # Crossing the floor by KEY NAME length, key value fixed at 1 byte ("0").
    name21_table = ctx.unique_name("sim2real-behav-ddbfloornm21-")
    ddb.create_table(
        TableName=name21_table,
        KeySchema=[{"AttributeName": "n" * 21, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "n" * 21, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name21_table))
    ddb.get_waiter("table_exists").wait(TableName=name21_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    # 21-byte name + 1-byte value = 22 pre-existing bytes: at the floor, still flat.
    _probe(ddb, name21_table, {"n" * 21: {"S": "0"}}, _FLAT_CEILING, 22)

    name22_table = ctx.unique_name("sim2real-behav-ddbfloornm22-")
    ddb.create_table(
        TableName=name22_table,
        KeySchema=[{"AttributeName": "n" * 22, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "n" * 22, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name22_table))
    ddb.get_waiter("table_exists").wait(TableName=name22_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    # 22-byte name + 1-byte value = 23 pre-existing bytes: one past the floor.
    _probe(ddb, name22_table, {"n" * 22: {"S": "0"}}, _FLAT_CEILING - 1, 23)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
