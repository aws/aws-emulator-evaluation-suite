"""update-item-size-floor-excludes-short-sort-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-size-floor-excludes-short-sort-key"
GROUP = "limits"
SERVICES = ["dynamodb"]

_ITEM_TOO_LARGE = ("ValidationException", "Item size to update has exceeded the maximum allowed size")

# Below _FLAT_FLOOR_BYTES of pre-existing attribute bytes, a standalone UpdateItem's size
# ceiling for a new attribute "v" is flat at 409600 - len("v") - _FLAT_FLOOR_BYTES,
# regardless of how those pre-existing bytes are distributed among the item's attributes.
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


def _probe(ddb, table, key: dict) -> int:
    """Seed key, confirm _FLAT_CEILING is the exact accept/refuse boundary for a bare
    ``SET v = :v`` write, and confirm the refused write left no trace.
    """
    ddb.put_item(TableName=table, Item=dict(key))
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                     ExpressionAttributeValues={":v": {"S": "x" * _FLAT_CEILING}})
    accepted = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert len(accepted.get("v", {}).get("S", "")) == _FLAT_CEILING, (
        f"a SET of {_FLAT_CEILING} bytes did not read back at that length: {accepted.get('v')!r}"
    )

    ddb.put_item(TableName=table, Item=dict(key))  # reset: no "v" attribute on the stored item
    _expect_error(
        lambda: ddb.update_item(TableName=table, Key=key, UpdateExpression="SET v = :v",
                                ExpressionAttributeValues={":v": {"S": "x" * (_FLAT_CEILING + 1)}}),
        *_ITEM_TOO_LARGE,
    )
    refused = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "v" not in refused, f"a refused SET of {_FLAT_CEILING + 1} bytes still created attribute v: {refused!r}"
    return _FLAT_CEILING


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A composite-key table's UpdateItem size ceiling equals a hash-only table's ceiling
    when the sort key's bytes keep the item's pre-existing bytes under the 22-byte floor.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")

    hash_table = ctx.unique_name("sim2real-behav-ddbfloorhash-")
    ddb.create_table(
        TableName=hash_table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=hash_table))
    ddb.get_waiter("table_exists").wait(TableName=hash_table, WaiterConfig={"Delay": 1, "MaxAttempts": 90})

    sort_table = ctx.unique_name("sim2real-behav-ddbfloorsort-")
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

    # Hash-only, 1-byte key: 2 pre-existing bytes, well under the floor.
    hash_ceiling = _probe(ddb, hash_table, {"k": {"S": "0"}})
    assert hash_ceiling == _FLAT_CEILING, (
        f"hash-only ceiling was {hash_ceiling!r}, expected the flat ceiling {_FLAT_CEILING!r}"
    )

    # Hash + a 1-byte sort key: 4 pre-existing bytes (still well under the floor). The
    # composite ceiling must equal the hash-only one -- the sort key's bytes do not yet
    # cost anything, unlike the 100-byte sort key regime where the per-byte charge binds.
    composite_ceiling = _probe(ddb, sort_table, {"k": {"S": "0"}, "s": {"S": "r"}})
    assert composite_ceiling == hash_ceiling, (
        f"a 1-byte sort key gave ceiling {composite_ceiling!r}; a hash-only table gave "
        f"{hash_ceiling!r} -- both should be the flat floor ceiling"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
