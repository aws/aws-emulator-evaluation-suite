"""batch-get-item-returns-complete-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-returns-complete-set"
GROUP = "batch"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem at the 100-key limit returns every requested item exactly once with its attributes
    and an empty UnprocessedKeys: the key-count boundary itself does not cause a partial response."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    expected = {f"key-{i}": str(i) for i in range(100)}
    for pk, val in expected.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": {"N": val}})

    resp = ddb.batch_get_item(
        RequestItems={
            table: {"Keys": [{"pk": {"S": pk}} for pk in expected], "ConsistentRead": True}
        }
    )

    unprocessed = resp.get("UnprocessedKeys", {})
    assert unprocessed == {}, f"expected no unprocessed keys for 100 tiny items, got {unprocessed}"

    items = resp["Responses"][table]
    assert len(items) == len(expected), (
        f"expected all {len(expected)} items back in one response, got {len(items)}"
    )

    seen_pks = [item["pk"]["S"] for item in items]
    assert len(seen_pks) == len(set(seen_pks)), (
        f"BatchGetItem returned a duplicate item at the 100-key boundary: {seen_pks}"
    )

    actual = {item["pk"]["S"]: item["val"]["N"] for item in items}
    assert actual == expected, (
        f"complete set mismatch at the 100-key boundary; symmetric difference "
        f"{sorted(set(actual) ^ set(expected))!r}"
    )


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-bgicomplete-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
