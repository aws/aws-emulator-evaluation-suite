"""empty-value-filter-expression-and-legacy-scan-filter-selection."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "empty-value-filter-expression-and-legacy-scan-filter-selection"
GROUP = "data-plane"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An empty String/Binary non-key attribute is stored and selectable: FilterExpression
    '= \"\"', begins_with(a, ''), size(a) = 0, and legacy ScanFilter EQ on an empty value each
    select exactly the items carrying that empty value, identically on the table and on a GSI.
    """
    ddb = ctx.client("dynamodb")
    table, index = _create_table(ctx)

    items = {
        "both-empty": {"pk": {"S": "both-empty"}, "gpk": {"S": "g1"}, "s": {"S": ""}, "b": {"B": b""}},
        "s-empty": {"pk": {"S": "s-empty"}, "gpk": {"S": "g2"}, "s": {"S": ""}, "b": {"B": b"z"}},
        "b-empty": {"pk": {"S": "b-empty"}, "gpk": {"S": "g3"}, "s": {"S": "w"}, "b": {"B": b""}},
        "neither-empty": {"pk": {"S": "neither-empty"}, "gpk": {"S": "g4"}, "s": {"S": "x"}, "b": {"B": b"y"}},
    }
    resp = ddb.batch_write_item(
        RequestItems={table: [{"PutRequest": {"Item": item}} for item in items.values()]}
    )
    assert resp["UnprocessedItems"] == {}, f"seeding left {resp['UnprocessedItems']!r} unprocessed"

    s_empty_ids = frozenset(k for k, v in items.items() if v["s"]["S"] == "")
    b_empty_ids = frozenset(k for k, v in items.items() if bytes(v["b"]["B"]) == b"")
    all_ids = frozenset(items)

    # GSI scans are eventually consistent: poll until the index has caught up with the seed,
    # bounded by the check's own remaining time budget rather than a fixed sleep.
    deadline = time.monotonic() + max(1.0, min(60.0, (ctx.time_left() or 60.0) - 10.0))
    seen = _scan(ddb, table, index)
    while seen != all_ids and time.monotonic() < deadline:
        time.sleep(2)
        seen = _scan(ddb, table, index)
    assert seen == all_ids, f"gsi {index!r} never converged to {all_ids!r}, last saw {seen!r}"

    for index_name in (None, index):
        eq = _scan(ddb, table, index_name, FilterExpression="s = :e",
                   ExpressionAttributeValues={":e": {"S": ""}})
        assert eq == s_empty_ids, f"s = '' on index={index_name!r} selected {eq!r}, expected {s_empty_ids!r}"

        bw = _scan(ddb, table, index_name, FilterExpression="begins_with(s, :e)",
                   ExpressionAttributeValues={":e": {"S": ""}})
        assert bw == all_ids, f"begins_with(s, '') on index={index_name!r} selected {bw!r}, expected {all_ids!r}"

        sz = _scan(ddb, table, index_name, FilterExpression="size(b) = :z",
                   ExpressionAttributeValues={":z": {"N": "0"}})
        assert sz == b_empty_ids, f"size(b) = 0 on index={index_name!r} selected {sz!r}, expected {b_empty_ids!r}"

        legacy = _scan(ddb, table, index_name,
                       ScanFilter={"b": {"ComparisonOperator": "EQ", "AttributeValueList": [{"B": b""}]}})
        assert legacy == b_empty_ids, (
            f"legacy ScanFilter EQ b='' on index={index_name!r} selected {legacy!r}, expected {b_empty_ids!r}"
        )


def _scan(ddb, table: str, index_name, **kwargs) -> frozenset:
    """Every page's `pk` values from a strongly consistent Scan, filtered as given."""
    extra = {"IndexName": index_name} if index_name else {}
    consistent = {} if index_name else {"ConsistentRead": True}
    ids: set = set()
    start = None
    while True:
        page_start = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=table, **extra, **consistent, **kwargs, **page_start)
        ids.update(i["pk"]["S"] for i in page.get("Items", []))
        start = page.get("LastEvaluatedKey")
        if not start:
            return frozenset(ids)


def _create_table(ctx) -> tuple:
    """A table with hash key pk (S) and a GSI by gpk (S), projecting all attributes."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    index = "by-gpk"
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": index,
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    return name, index


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
