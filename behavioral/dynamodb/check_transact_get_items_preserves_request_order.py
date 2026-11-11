"""transact-get-items-preserves-request-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-preserves-request-order"
GROUP = "ordering"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems returns item responses in the exact order of the requested
    TransactItems, including an empty entry for a key that does not exist."""
    ddb = ctx.client("dynamodb")
    table_name = _create_table(ctx)

    for i in range(1, 4):
        ddb.put_item(
            TableName=table_name,
            Item={"pk": {"S": f"item-{i}"}, "val": {"S": f"value-{i}"}},
        )

    # Deliberately out-of-order, interleaved with a key that does not exist.
    requested_order = ["item-3", "item-missing", "item-1", "item-2"]
    transact_items = [
        {"Get": {"TableName": table_name, "Key": {"pk": {"S": k}}}}
        for k in requested_order
    ]

    resp = ddb.transact_get_items(TransactItems=transact_items)
    responses = resp["Responses"]
    assert len(responses) == len(requested_order), (
        f"expected {len(requested_order)} responses, got {len(responses)}"
    )

    for key, entry in zip(requested_order, responses):
        if key == "item-missing":
            assert not entry.get("Item"), (
                f"expected empty response entry for missing key, got {entry}"
            )
        else:
            item = entry.get("Item")
            assert item is not None, f"expected an item for {key}, got empty response"
            assert item["pk"]["S"] == key, (
                f"order mismatch: expected {key} at this position, got {item['pk']['S']}"
            )
            expected_val = f"value-{key.split('-')[1]}"
            assert item["val"]["S"] == expected_val, (
                f"expected val={expected_val} for {key}, got {item['val']}"
            )

    # Sanity: a second traversal in a different order must reorder the responses
    # accordingly, proving the order tracks the request rather than some fixed
    # internal ordering (e.g. insertion order).
    reversed_order = list(reversed(requested_order))
    resp2 = ddb.transact_get_items(
        TransactItems=[
            {"Get": {"TableName": table_name, "Key": {"pk": {"S": k}}}}
            for k in reversed_order
        ]
    )
    got_keys = [
        entry.get("Item", {}).get("pk", {}).get("S", "item-missing")
        for entry in resp2["Responses"]
    ]
    assert got_keys == reversed_order, (
        f"reversed request order not reflected: expected {reversed_order}, got {got_keys}"
    )


def _create_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-tgi-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
