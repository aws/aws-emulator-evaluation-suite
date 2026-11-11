"""update-item-size-ceiling-counts-key-and-untouched-attribute-bytes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-size-ceiling-counts-key-and-untouched-attribute-bytes"
GROUP = "limits"
SERVICES = ["dynamodb"]

_ITEM_TOO_LARGE = ("ValidationException",
                   "Item size to update has exceeded the maximum allowed size")

# DynamoDB takes the LOOSER of two caps on a standalone UpdateItem that writes one new string
# attribute "v": the finished item must stay <= 409600 bytes, and "v"'s own name+value must stay
# <= 409600 - _FLAT_FLOOR_BYTES bytes on their own. Below _FLAT_FLOOR_BYTES bytes of pre-existing
# attributes (the key's, a sort key's, an untouched attribute's -- none of them excluded) the
# second cap binds and the ceiling is flat; past it the first cap binds and costs byte for byte.
_CAP = 409600
_FLAT_FLOOR_BYTES = 22
_V_NAME_LEN = 1  # len("v")


def _ceiling(preexisting_bytes: int) -> int:
    """Max accepted length of the string value a bare ``SET v = :v`` writes."""
    return _CAP - _V_NAME_LEN - max(preexisting_bytes, _FLAT_FLOOR_BYTES)


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected UpdateItem to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _attr_bytes(name: str, value: dict) -> int:
    return len(name) + len(value["S"])


def _probe(ddb, table, key: dict, *, extra_item: dict | None = None) -> int:
    """Seed key (+ extra_item), confirm the predicted ceiling is the exact accept/refuse boundary
    for a ``SET v = :v`` write, confirm the refused write left no trace, and return the ceiling.
    """
    item = dict(key)
    if extra_item:
        item.update(extra_item)
    preexisting = sum(_attr_bytes(n, v) for n, v in item.items())
    ceiling = _ceiling(preexisting)

    ddb.put_item(TableName=table, Item=item)
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                     ExpressionAttributeValues={":v": {"S": "x" * ceiling}})
    accepted = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert accepted.get("v", {}).get("S", "") != "" and len(accepted["v"]["S"]) == ceiling, (
        f"a SET of {ceiling} bytes (the predicted ceiling for {preexisting} pre-existing bytes) "
        f"did not read back at that length: {accepted.get('v')!r}"
    )

    ddb.put_item(TableName=table, Item=item)  # reset: no "v" attribute on the stored item
    expect_error(
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                                ExpressionAttributeValues={":v": {"S": "x" * (ceiling + 1)}}),
        *_ITEM_TOO_LARGE,
    )
    refused = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "v" not in refused, f"a refused SET of {ceiling + 1} bytes still created attribute v: {refused!r}"
    return ceiling


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standalone UpdateItem's size ceiling for the attribute it writes is 409600 minus
    whichever is larger: 22, or the bytes every other attribute in the item occupies -- the
    key's, a sort key's and an untouched attribute's bytes all count, identically in us-east-1.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")
    use1 = ctx.client("dynamodb", region="us-east-1")  # region-pinned: the same ceiling is asserted in a second region

    table = ctx.unique_name("sim2real-behav-ddbupdceil-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    sort_table = ctx.unique_name("sim2real-behav-ddbupdceilsk-")
    ddb.create_table(
        TableName=sort_table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}, {"AttributeName": "s", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"},
                              {"AttributeName": "s", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=sort_table))
    ddb.get_waiter("table_exists").wait(TableName=sort_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    long_name = "a" * 100
    name_table = ctx.unique_name("sim2real-behav-ddbupdceilnm-")
    ddb.create_table(
        TableName=name_table,
        KeySchema=[{"AttributeName": long_name, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": long_name, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name_table))
    ddb.get_waiter("table_exists").wait(TableName=name_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    # A 1-byte key leaves 2 pre-existing bytes, well under the 22-byte floor: the flat ceiling
    # binds, and it sits below 409600 -- the written attribute's own cap, not the finished item's.
    key1 = {"k": {"S": "0"}}
    flat = _probe(ddb, table, key1)
    assert flat == _CAP - _V_NAME_LEN - _FLAT_FLOOR_BYTES, (
        f"a 1-byte key's ceiling was {flat!r}, expected the flat floor "
        f"{_CAP - _V_NAME_LEN - _FLAT_FLOOR_BYTES!r}"
    )

    # Exactly at the 22-byte floor the ceiling is still flat; one byte past it, the ceiling
    # drops by exactly that one byte -- the transition from the flat cap to the per-byte one.
    at_floor = _probe(ddb, table, key1, extra_item={"u": {"S": "z" * 19}})
    assert at_floor == flat, f"22 pre-existing bytes gave ceiling {at_floor!r}, expected the flat {flat!r}"
    past_floor = _probe(ddb, table, key1, extra_item={"u": {"S": "z" * 20}})
    assert past_floor == flat - 1, (
        f"23 pre-existing bytes gave ceiling {past_floor!r}, expected exactly one less than the "
        f"flat ceiling {flat!r}"
    )

    # A longer key VALUE is not excluded: its bytes cost the ceiling byte for byte past the floor.
    key_v100 = {"k": {"S": "y" * 100}}
    by_value = _probe(ddb, table, key_v100)
    assert by_value == _CAP - _V_NAME_LEN - 101, (
        f"a 100-byte key value gave ceiling {by_value!r}, expected {_CAP - _V_NAME_LEN - 101!r}"
    )

    key_v1024 = {"k": {"S": "y" * 1024}}
    by_value_1024 = _probe(ddb, table, key_v1024)
    assert by_value_1024 == _CAP - _V_NAME_LEN - 1025, (
        f"a 1024-byte key value gave ceiling {by_value_1024!r}, expected {_CAP - _V_NAME_LEN - 1025!r}"
    )

    # A longer key NAME costs exactly the same as the same number of bytes in the key value.
    key_name100 = {long_name: {"S": "0"}}
    by_name = _probe(ddb, name_table, key_name100)
    assert by_name == by_value, (
        f"a 100-byte key name gave ceiling {by_name!r}; a 100-byte key value gave {by_value!r} -- "
        f"key-name and key-value bytes must cost the ceiling the same"
    )

    # A sort key's bytes are not excluded either: they cost exactly what any other attribute's do.
    key_sorted = {"k": {"S": "0"}, "s": {"S": "r" * 100}}
    by_sort = _probe(ddb, sort_table, key_sorted)
    assert by_sort == _CAP - _V_NAME_LEN - 103, (
        f"a 100-byte sort key value gave ceiling {by_sort!r}, expected {_CAP - _V_NAME_LEN - 103!r}"
    )

    # Identical in us-east-1: the rule is not regional.
    use1_table = ctx.unique_name("sim2real-behav-ddbupdceilue1-")
    use1.create_table(
        TableName=use1_table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: use1.delete_table(TableName=use1_table))
    use1.get_waiter("table_exists").wait(TableName=use1_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    use1_flat = _probe(use1, use1_table, key1)
    assert use1_flat == flat, f"us-east-1's flat ceiling was {use1_flat!r}, expected {flat!r} as in us-west-2"
    use1_by_value = _probe(use1, use1_table, key_v100)
    assert use1_by_value == by_value, (
        f"us-east-1's ceiling for a 100-byte key value was {use1_by_value!r}, expected {by_value!r} "
        "as in us-west-2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
