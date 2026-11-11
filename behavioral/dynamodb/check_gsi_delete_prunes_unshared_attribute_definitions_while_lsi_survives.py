"""gsi-delete-prunes-unshared-attribute-definitions-while-lsi-survives."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-delete-prunes-unshared-attribute-definitions-while-lsi-survives"
GROUP = "gsi"
SERVICES = ["dynamodb"]


def _wait_table_settled(ddb, name, timeout_s=1500.0, interval_s=5.0):
    """Poll DescribeTable until the table and every index are ACTIVE."""
    deadline = time.monotonic() + timeout_s
    table = None
    while time.monotonic() < deadline:
        table = ddb.describe_table(TableName=name)["Table"]
        busy = [
            i for i in table.get("GlobalSecondaryIndexes") or [] if i.get("IndexStatus") != "ACTIVE"
        ]
        if table["TableStatus"] == "ACTIVE" and not busy:
            return table
        time.sleep(interval_s)
    raise AssertionError(f"{name} never settled to ACTIVE within {timeout_s}s; last={table!r}")


def _wait_gsi_query_matches(ddb, table, index_name, key_condition, values, timeout_s=60.0, interval_s=1.0):
    """Poll a GSI Query until it reflects a write (GSIs are eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = ddb.query(
            TableName=table,
            IndexName=index_name,
            KeyConditionExpression=key_condition,
            ExpressionAttributeValues=values,
        )
        if result["Count"] >= 1:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"GSI {index_name} never reflected the write within {timeout_s}s; last={result!r}")


def _wait_gsi_gone(ddb, name, index_name, timeout_s=1500.0, interval_s=5.0):
    """Poll DescribeTable until ``index_name`` no longer appears among the GSIs."""
    deadline = time.monotonic() + timeout_s
    table = None
    while time.monotonic() < deadline:
        table = ddb.describe_table(TableName=name)["Table"]
        names = [g["IndexName"] for g in table.get("GlobalSecondaryIndexes") or []]
        if table["TableStatus"] == "ACTIVE" and index_name not in names:
            return table
        time.sleep(interval_s)
    raise AssertionError(f"{index_name} still present on {name} after {timeout_s}s; last={table!r}")


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Deleting a GSI drops only the AttributeDefinitions no surviving key uses: an
    attribute that is also an LSI sort key stays declared, and base-table PutItem,
    GetItem and Query keep serving the item afterward.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsilsi-")

    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "shared_attr", "AttributeType": "S"},
            {"AttributeName": "gsi_only_sort", "AttributeType": "S"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi-main",
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "shared_attr", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi-main",
                "KeySchema": [
                    {"AttributeName": "shared_attr", "KeyType": "HASH"},
                    {"AttributeName": "gsi_only_sort", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_settled(ddb, table)

    item = {
        "pk": {"S": "item-a"},
        "sk": {"S": "sort-a"},
        "shared_attr": {"S": "shared-value"},
        "gsi_only_sort": {"S": "gsi-sort-value"},
    }
    ddb.put_item(TableName=table, Item=item)

    # Positive control before the delete: the GSI serves the item on its own key, once the
    # eventually-consistent index catches up with the write.
    before = _wait_gsi_query_matches(
        ddb,
        table,
        "gsi-main",
        "shared_attr = :s AND gsi_only_sort = :g",
        {":s": {"S": "shared-value"}, ":g": {"S": "gsi-sort-value"}},
    )
    assert before["Count"] == 1 and before["Items"][0]["pk"] == {"S": "item-a"}, (
        f"expected the GSI to serve item-a before deletion, got {before['Items']!r}"
    )

    ddb.update_table(
        TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "gsi-main"}}]
    )
    deleted = _wait_gsi_gone(ddb, table, "gsi-main")

    deleted_attrs = {a["AttributeName"]: a["AttributeType"] for a in deleted["AttributeDefinitions"]}
    assert deleted_attrs == {"pk": "S", "sk": "S", "shared_attr": "S"}, (
        "expected AttributeDefinitions to keep the table keys plus the LSI's sort key "
        f"({{'pk': 'S', 'sk': 'S', 'shared_attr': 'S'}}) and drop gsi_only_sort, "
        f"got {deleted_attrs!r}"
    )
    lsi_names = [i["IndexName"] for i in deleted.get("LocalSecondaryIndexes") or []]
    assert lsi_names == ["lsi-main"], f"expected lsi-main to survive the GSI delete, got {lsi_names!r}"

    # Base-table PutItem still works after the index removal.
    second_item = {
        "pk": {"S": "item-b"},
        "sk": {"S": "sort-b"},
        "shared_attr": {"S": "shared-value-2"},
    }
    ddb.put_item(TableName=table, Item=second_item)

    got = ddb.get_item(
        TableName=table,
        Key={"pk": {"S": "item-b"}, "sk": {"S": "sort-b"}},
        ConsistentRead=True,
    )
    assert got.get("Item") == second_item, f"expected GetItem to return {second_item!r}, got {got.get('Item')!r}"

    queried = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :p AND sk = :s",
        ExpressionAttributeValues={":p": {"S": "item-b"}, ":s": {"S": "sort-b"}},
        ConsistentRead=True,
    )
    assert queried["Count"] == 1 and queried["Items"][0] == second_item, (
        f"expected base-table Query to return {second_item!r}, got {queried['Items']!r}"
    )

    # The surviving LSI still serves the attribute it shared with the deleted GSI.
    lsi_hit = ddb.query(
        TableName=table,
        IndexName="lsi-main",
        KeyConditionExpression="pk = :p AND shared_attr = :s",
        ExpressionAttributeValues={":p": {"S": "item-a"}, ":s": {"S": "shared-value"}},
        ConsistentRead=True,
    )
    assert lsi_hit["Count"] == 1 and lsi_hit["Items"][0]["pk"] == {"S": "item-a"}, (
        f"expected lsi-main to still serve item-a by shared_attr, got {lsi_hit['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
