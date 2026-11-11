"""partiql-ordering-binary-byte-order-and-string-number-cross-type-match."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-ordering-binary-byte-order-and-string-number-cross-type-match"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqlord-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return ddb, name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL ordering comparator against a parameterized Binary value orders by unsigned
    byte value (0x01 < 0x80), and the same comparator between a String attribute and a Number
    parameter is accepted and matches no item.
    """
    ddb, table = _table(ctx)

    item = {"pk": {"S": "row"}, "bin": {"B": b"\x01"}, "strv": {"S": "abc"}}
    ddb.put_item(TableName=table, Item=item)

    stored = ddb.get_item(TableName=table, Key={"pk": {"S": "row"}}, ConsistentRead=True)["Item"]
    assert stored == item, f"item changed on the way back from PutItem/GetItem: {stored!r}"

    # Positive control: a parameterized Binary equality comparison finds the item, so the
    # mechanism for binding a Binary parameter into a WHERE clause works before ordering is tried.
    eq = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND bin = ?',
        Parameters=[{"S": "row"}, {"B": b"\x01"}],
        ConsistentRead=True,
    )
    assert eq["Items"] == [item], f"bin = B'\\x01' must find the stored item, got {eq['Items']!r}"

    less = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND bin < ?',
        Parameters=[{"S": "row"}, {"B": b"\x80"}],
        ConsistentRead=True,
    )
    assert less["Items"] == [item], (
        f"bin < B'\\x80' must match the stored byte 0x01 by unsigned byte order, got {less['Items']!r}"
    )

    greater = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND bin > ?',
        Parameters=[{"S": "row"}, {"B": b"\x80"}],
        ConsistentRead=True,
    )
    assert greater["Items"] == [], (
        f"bin > B'\\x80' must not match the stored byte 0x01 by unsigned byte order, got {greater['Items']!r}"
    )

    # Positive control: a same-type (String) ordering comparison matches, so the empty result
    # below is attributable to the cross-type comparison, not to '<' being broken for strv.
    same_type = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND strv < ?',
        Parameters=[{"S": "row"}, {"S": "xyz"}],
        ConsistentRead=True,
    )
    assert same_type["Items"] == [item], f"strv < 'xyz' must match the stored item, got {same_type['Items']!r}"

    cross_type = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND strv < ?',
        Parameters=[{"S": "row"}, {"N": "5"}],
        ConsistentRead=True,
    )
    assert cross_type["Items"] == [], (
        f"strv < N'5' must be accepted and match nothing; got {cross_type['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
