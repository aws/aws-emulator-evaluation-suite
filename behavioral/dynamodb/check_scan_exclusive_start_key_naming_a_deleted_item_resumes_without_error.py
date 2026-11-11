"""scan-exclusive-start-key-naming-a-deleted-item-resumes-without-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-exclusive-start-key-naming-a-deleted-item-resumes-without-error"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_N = 16
_PAGE = 5


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan resumes from an ExclusiveStartKey naming an item deleted since it was issued.

    The call succeeds, the filter is applied to items found after the key's position,
    and exactly the items not yet seen are returned.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    _create_table(ctx, ddb, table)

    all_pks = {f"item-{i:03d}" for i in range(_N)}
    for pk in sorted(all_pks):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "category": {"S": "keep"}})

    page1 = ddb.scan(TableName=table, Limit=_PAGE, ConsistentRead=True)
    assert len(page1["Items"]) == _PAGE, (
        f"first page returned {len(page1['Items'])} item(s), expected {_PAGE}"
    )
    assert "LastEvaluatedKey" in page1, "expected a LastEvaluatedKey after the first page"
    lek = page1["LastEvaluatedKey"]
    page1_pks = {item["pk"]["S"] for item in page1["Items"]}
    deleted_pk = lek["pk"]["S"]
    assert deleted_pk in page1_pks, (
        f"LastEvaluatedKey names {deleted_pk!r}, not one of the first page's items {sorted(page1_pks)!r}"
    )

    ddb.update_item(
        TableName=table, Key={"pk": {"S": deleted_pk}},
        UpdateExpression="SET category = :drop",
        ExpressionAttributeValues={":drop": {"S": "drop"}},
    )
    changed = ddb.get_item(TableName=table, Key={"pk": {"S": deleted_pk}}, ConsistentRead=True)
    assert changed["Item"]["category"]["S"] == "drop", (
        f"expected {deleted_pk!r}'s category to read back as 'drop', got {changed['Item']['category']!r}"
    )

    ddb.delete_item(TableName=table, Key={"pk": {"S": deleted_pk}})
    gone = ddb.get_item(TableName=table, Key={"pk": {"S": deleted_pk}}, ConsistentRead=True)
    assert "Item" not in gone, f"expected {deleted_pk!r} absent after DeleteItem, got {gone.get('Item')!r}"

    resumed_pks: set[str] = set()
    params = {
        "TableName": table, "ConsistentRead": True, "ExclusiveStartKey": lek,
        "FilterExpression": "category = :want",
        "ExpressionAttributeValues": {":want": {"S": "keep"}},
    }
    while True:
        resp = ddb.scan(**params)
        for item in resp["Items"]:
            assert item["category"]["S"] == "keep", (
                f"filtered Scan returned {item['pk']['S']!r} with category "
                f"{item['category']['S']!r}, expected only 'keep'"
            )
        page_pks = {item["pk"]["S"] for item in resp["Items"]}
        assert page_pks.isdisjoint(page1_pks), (
            f"resumed Scan returned {sorted(page_pks & page1_pks)!r}, already seen on the first page"
        )
        resumed_pks |= page_pks
        if "LastEvaluatedKey" not in resp:
            break
        params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    expected_resumed = all_pks - page1_pks
    assert resumed_pks == expected_resumed, (
        f"resuming after the deleted item's key returned {sorted(resumed_pks)!r}, "
        f"expected exactly the items past the first page {sorted(expected_resumed)!r}"
    )

    final_pks: set[str] = set()
    final_params: dict = {"TableName": table, "ConsistentRead": True}
    while True:
        resp = ddb.scan(**final_params)
        final_pks |= {item["pk"]["S"] for item in resp["Items"]}
        if "LastEvaluatedKey" not in resp:
            break
        final_params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    assert final_pks == all_pks - {deleted_pk}, (
        f"expected the table to hold every item but {deleted_pk!r}, got {sorted(final_pks)!r}"
    )


def _create_table(ctx, ddb, name: str) -> None:
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _drop_table(ddb, name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})


def _drop_table(ddb, name: str) -> None:
    """Teardown: a CREATING table refuses DeleteTable, so wait for it to settle first (bounded)."""
    from botocore.exceptions import ClientError

    try:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "DELETING":
            return
        if status != "ACTIVE":
            ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
