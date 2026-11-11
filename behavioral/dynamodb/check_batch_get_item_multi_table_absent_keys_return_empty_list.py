"""batch-get-item-multi-table-absent-keys-return-empty-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-multi-table-absent-keys-return-empty-list"
GROUP = "batch"
SERVICES = ["dynamodb"]


def _simple_table(ctx, ddb, prefix):
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
    """A BatchGetItem across two tables, naming only keys absent from each, returns an empty list
    under each table's own key in Responses rather than omitting the table or erroring.
    """
    ddb = ctx.client("dynamodb")
    table_a = _simple_table(ctx, ddb, "sim2real-behav-bgiabs-a-")
    table_b = _simple_table(ctx, ddb, "sim2real-behav-bgiabs-b-")

    # Positive control: each table answers with its own present item before asserting on keys
    # that are absent from both.
    ddb.put_item(TableName=table_a, Item={"pk": {"S": "present"}})
    ddb.put_item(TableName=table_b, Item={"pk": {"S": "present"}})
    control = ddb.batch_get_item(RequestItems={
        table_a: {"Keys": [{"pk": {"S": "present"}}], "ConsistentRead": True},
        table_b: {"Keys": [{"pk": {"S": "present"}}], "ConsistentRead": True},
    })
    assert control["Responses"][table_a] == [{"pk": {"S": "present"}}], control["Responses"][table_a]
    assert control["Responses"][table_b] == [{"pk": {"S": "present"}}], control["Responses"][table_b]

    resp = ddb.batch_get_item(RequestItems={
        table_a: {"Keys": [{"pk": {"S": "missing-a1"}}, {"pk": {"S": "missing-a2"}}], "ConsistentRead": True},
        table_b: {"Keys": [{"pk": {"S": "missing-b1"}}], "ConsistentRead": True},
    })
    assert resp["Responses"].get(table_a) == [], (
        f"table_a with no matching keys must map to an empty list, got {resp['Responses'].get(table_a)!r}"
    )
    assert resp["Responses"].get(table_b) == [], (
        f"table_b with no matching keys must map to an empty list, got {resp['Responses'].get(table_b)!r}"
    )
    assert resp.get("UnprocessedKeys", {}) == {}, resp.get("UnprocessedKeys")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
