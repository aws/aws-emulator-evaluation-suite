"""update-item-remove-missing-map-key-noop-and-set-empty-list-index."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-remove-missing-map-key-noop-and-set-empty-list-index"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


def _table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-ddbnp-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem REMOVE of a map key that does not exist is a true no-op, and SET l[0] on a
    stored empty list stores a single-element list.
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx, ddb)

    key = {"pk": {"S": "has-map"}}
    seeded = {**key, "m": {"M": {"present": {"S": "x"}}}}
    ddb.put_item(TableName=t, Item=seeded)

    resp = ddb.update_item(
        TableName=t, Key=key, UpdateExpression="REMOVE m.#missing",
        ExpressionAttributeNames={"#missing": "missing"},
        ReturnValues="ALL_NEW",
    )
    assert resp["Attributes"] == seeded, (
        f"REMOVE m.missing where 'missing' was never a key of m returned ALL_NEW "
        f"{resp['Attributes']!r}, expected the item unchanged {seeded!r}"
    )
    after = _stored(ddb, t, "has-map")
    assert after == seeded, (
        f"GetItem after the no-op REMOVE returned {after!r}, expected it unchanged {seeded!r}"
    )

    # Positive control: REMOVE of a key that IS present actually removes it, so the no-op above
    # is about the missing key, not a broken REMOVE.
    resp2 = ddb.update_item(
        TableName=t, Key=key, UpdateExpression="REMOVE m.#present",
        ExpressionAttributeNames={"#present": "present"},
        ReturnValues="ALL_NEW",
    )
    assert resp2["Attributes"] == {**key, "m": {"M": {}}}, (
        f"REMOVE m.present returned ALL_NEW {resp2['Attributes']!r}, expected an emptied map"
    )

    key2 = {"pk": {"S": "empty-list"}}
    seeded2 = {**key2, "l": {"L": []}}
    ddb.put_item(TableName=t, Item=seeded2)

    resp3 = ddb.update_item(
        TableName=t, Key=key2, UpdateExpression="SET l[0] = :v",
        ExpressionAttributeValues={":v": {"S": "only"}},
        ReturnValues="ALL_NEW",
    )
    assert resp3["Attributes"] == {**key2, "l": {"L": [{"S": "only"}]}}, (
        f"SET l[0] on a stored empty list returned ALL_NEW {resp3['Attributes']!r}, expected a "
        f"single-element list [only]"
    )
    after2 = _stored(ddb, t, "empty-list")
    assert after2 == {**key2, "l": {"L": [{"S": "only"}]}}, (
        f"GetItem after SET l[0] on an empty list returned {after2!r}, expected [only]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
