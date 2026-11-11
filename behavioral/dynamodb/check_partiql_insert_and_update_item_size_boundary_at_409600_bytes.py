"""partiql-insert-and-update-item-size-boundary-at-409600-bytes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-insert-and-update-item-size-boundary-at-409600-bytes"
GROUP = "partiql"
SERVICES = ["dynamodb"]
LIMIT_BYTES = 409600

_INSERT_OVER = ("ValidationException", "Item size has exceeded the maximum allowed size")
_UPDATE_OVER = ("ValidationException", "Item size to update has exceeded the maximum allowed size")


def _filler_len(pk_value: str, filler_attr: str, total_bytes: int) -> int:
    """The filler-attribute byte length so a one-pk item's encoded size is exactly total_bytes."""
    overhead = len("pk".encode()) + len(pk_value.encode()) + len(filler_attr.encode())
    filler_len = total_bytes - overhead
    assert filler_len > 0, f"{total_bytes} bytes is too small for this item shape"
    return filler_len


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"unexpected message {got_message!r}"
        return
    raise AssertionError(f"expected the call to be refused with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL INSERT stores an item at exactly the 409600-byte limit and refuses one byte
    over with the put wording; a PartiQL UPDATE growing to exactly 409600 bytes stores it too,
    refusing one byte past with the update wording, and leaving the refused item untouched.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-partiql-size-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # INSERT: exactly at the limit is accepted and reads back whole.
    insert_at_pk = "insert-at-limit"
    insert_at_value = "x" * _filler_len(insert_at_pk, "data", LIMIT_BYTES)
    ddb.execute_statement(
        Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': ?, 'data': ?}}",
        Parameters=[{"S": insert_at_pk}, {"S": insert_at_value}],
    )
    got = ddb.get_item(TableName=table, Key={"pk": {"S": insert_at_pk}}, ConsistentRead=True).get("Item", {})
    assert got.get("data", {}).get("S") == insert_at_value, (
        f"a {LIMIT_BYTES}-byte item must round-trip whole through PartiQL INSERT, "
        f"got {len(got.get('data', {}).get('S', ''))} bytes back"
    )

    # INSERT: one byte over the limit is refused and nothing is stored.
    insert_over_pk = "insert-over-limit"
    insert_over_value = "x" * _filler_len(insert_over_pk, "data", LIMIT_BYTES + 1)
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': ?, 'data': ?}}",
            Parameters=[{"S": insert_over_pk}, {"S": insert_over_value}],
        ),
        *_INSERT_OVER,
    )
    rejected = ddb.get_item(TableName=table, Key={"pk": {"S": insert_over_pk}}, ConsistentRead=True)
    assert "Item" not in rejected, f"a PartiQL INSERT refused for size must not persist, got {rejected.get('Item')}"

    # UPDATE: growing to exactly the limit is accepted and reads back whole.
    update_at_pk = "update-at-limit"
    ddb.put_item(TableName=table, Item={"pk": {"S": update_at_pk}})
    update_at_value = "x" * _filler_len(update_at_pk, "bigattr", LIMIT_BYTES)
    ddb.execute_statement(
        Statement=f"UPDATE \"{table}\" SET bigattr = ? WHERE pk = ?",
        Parameters=[{"S": update_at_value}, {"S": update_at_pk}],
    )
    updated = ddb.get_item(TableName=table, Key={"pk": {"S": update_at_pk}}, ConsistentRead=True).get("Item", {})
    assert updated.get("bigattr", {}).get("S") == update_at_value, (
        f"growing an item to exactly {LIMIT_BYTES} bytes via PartiQL UPDATE must store whole, "
        f"got {len(updated.get('bigattr', {}).get('S', ''))} bytes back"
    )

    # UPDATE: growing one byte past the limit is refused and the item is left unchanged.
    update_over_pk = "update-over-limit"
    ddb.put_item(TableName=table, Item={"pk": {"S": update_over_pk}})
    update_over_value = "x" * _filler_len(update_over_pk, "bigattr", LIMIT_BYTES + 1)
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{table}\" SET bigattr = ? WHERE pk = ?",
            Parameters=[{"S": update_over_value}, {"S": update_over_pk}],
        ),
        *_UPDATE_OVER,
    )
    unchanged = ddb.get_item(TableName=table, Key={"pk": {"S": update_over_pk}}, ConsistentRead=True).get("Item", {})
    assert "bigattr" not in unchanged, (
        f"a PartiQL UPDATE refused for size must leave the item unchanged, got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
