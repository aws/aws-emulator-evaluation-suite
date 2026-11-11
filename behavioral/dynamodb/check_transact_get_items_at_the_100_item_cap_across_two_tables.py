"""transact-get-items-at-the-100-item-cap-across-two-tables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-at-the-100-item-cap-across-two-tables"
GROUP = "transactions"
SERVICES = ["dynamodb"]


def _create_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems at the 100-action limit, split across two tables, returns
    exactly 100 Responses in request order with each slot resolved against its own table."""
    ddb = ctx.client("dynamodb")
    table_a = _create_table(ctx, ddb, "sim2real-behav-tgi100-a-")
    table_b = _create_table(ctx, ddb, "sim2real-behav-tgi100-b-")

    transact_items = []
    for i in range(100):
        table = table_a if i % 2 == 0 else table_b
        key = {"pk": {"S": f"k{i}"}}
        ddb.put_item(TableName=table, Item={**key, "slot": {"N": str(i)}})
        transact_items.append({"Get": {"TableName": table, "Key": key}})

    resp = ddb.transact_get_items(TransactItems=transact_items)
    responses = resp["Responses"]
    assert len(responses) == 100, f"expected 100 response slots, got {len(responses)}: {responses!r}"
    for i, entry in enumerate(responses):
        item = entry.get("Item")
        assert item is not None, f"slot {i} came back empty, expected the item put at request index {i}"
        got = item["slot"]["N"]
        assert got == str(i), f"slot {i} carried N {got!r}, expected the request-order value {str(i)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
