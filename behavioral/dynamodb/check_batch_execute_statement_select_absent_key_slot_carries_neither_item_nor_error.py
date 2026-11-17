"""batch-execute-statement-select-absent-key-slot-carries-neither-item-nor-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-select-absent-key-slot-carries-neither-item-nor-error"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return t


def _select(table: str, pk: str) -> dict:
    return {
        "Statement": f'SELECT * FROM "{table}" WHERE pk = ?',
        "Parameters": [{"S": pk}],
        "ConsistentRead": True,
    }


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement answers each SELECT by its position: a miss carries no
    Item and no Error, flanking hits carry their exact stored items, and writing the
    missing key turns every slot in the same statement order into a hit.
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)
    item_a = {"pk": {"S": "slot-a"}, "val": {"S": "alpha"}}
    item_c = {"pk": {"S": "slot-c"}, "val": {"S": "gamma"}}
    ddb.put_item(TableName=t, Item=item_a)
    ddb.put_item(TableName=t, Item=item_c)

    resp = ddb.batch_execute_statement(Statements=[
        _select(t, "slot-a"), _select(t, "slot-b"), _select(t, "slot-c"),
    ])
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses!r}"
    slot_a, slot_b, slot_c = responses

    assert slot_a == {"TableName": t, "Item": item_a}, (
        f"expected slot 0 to carry exactly table {t!r} and Item {item_a!r}, got {slot_a!r}"
    )
    assert slot_c == {"TableName": t, "Item": item_c}, (
        f"expected slot 2 to carry exactly table {t!r} and Item {item_c!r}, got {slot_c!r}"
    )
    assert slot_b == {"TableName": t}, (
        f"expected the miss at slot 1 to carry neither Item nor Error, got {slot_b!r}"
    )

    missing_item = {"pk": {"S": "slot-b"}, "val": {"S": "beta"}}
    ddb.put_item(TableName=t, Item=missing_item)

    resp2 = ddb.batch_execute_statement(Statements=[
        _select(t, "slot-b"), _select(t, "slot-a"), _select(t, "slot-c"),
    ])
    responses2 = resp2["Responses"]
    assert len(responses2) == 3, f"expected 3 per-statement responses, got {len(responses2)}: {responses2!r}"
    slot_b2, slot_a2, slot_c2 = responses2

    assert slot_b2 == {"TableName": t, "Item": missing_item}, (
        f"expected the newly written key's slot to equal {missing_item!r}, got {slot_b2!r}"
    )
    assert slot_a2 == {"TableName": t, "Item": item_a}, (
        f"expected the sibling hit to equal {item_a!r}, got {slot_a2!r}"
    )
    assert slot_c2 == {"TableName": t, "Item": item_c}, (
        f"expected the sibling hit to equal {item_c!r}, got {slot_c2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
