"""legacy-attributes-to-get-empty-item-and-whole-nested-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "legacy-attributes-to-get-empty-item-and-whole-nested-values"
GROUP = "legacy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """Legacy AttributesToGet naming none of an item's attributes returns an empty Item
    (GetItem) or an empty entry (BatchGetItem), not an absent one; a base-table Query and
    Scan project to exactly the named set, and a List or Map attribute comes back whole.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbattg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "p1"}, "sk": {"S": "s1"}}
    tags_list = {"L": [{"S": "red"}, {"S": "blue"}]}
    meta_map = {"M": {"x": {"S": "1"}, "y": {"S": "2"}}}
    ddb.put_item(TableName=table, Item={
        **key, "name": {"S": "alpha"}, "status": {"S": "active"},
        "tags": tags_list, "meta": meta_map,
    })

    # GetItem: the item exists but holds none of the two named attributes -- the response
    # carries an Item key whose value is an empty dict, not an absent Item.
    none_matching = ddb.get_item(TableName=table, Key=key, AttributesToGet=["phone", "address"],
                                 ConsistentRead=True)
    assert "Item" in none_matching, f"expected an Item key even though nothing matched: {none_matching!r}"
    assert none_matching["Item"] == {}, f"expected an empty Item, got {none_matching['Item']!r}"

    # Positive control: the same item, naming an attribute it does have.
    control = ddb.get_item(TableName=table, Key=key, AttributesToGet=["name"], ConsistentRead=True)
    assert control["Item"] == {"name": {"S": "alpha"}}, f"control GetItem returned {control['Item']!r}"

    # BatchGetItem: the per-item entry is an empty dict, present in the Responses list rather
    # than the item being dropped from it.
    none_matching_batch = ddb.batch_get_item(RequestItems={
        table: {"Keys": [key], "AttributesToGet": ["phone", "address"], "ConsistentRead": True}})
    assert none_matching_batch["Responses"][table] == [{}], (
        f"expected a single empty-dict entry, got {none_matching_batch['Responses'][table]!r}"
    )

    # Positive control: same Keys, naming an attribute the item has.
    control_batch = ddb.batch_get_item(RequestItems={
        table: {"Keys": [key], "AttributesToGet": ["name"], "ConsistentRead": True}})
    assert control_batch["Responses"][table] == [{"name": {"S": "alpha"}}], (
        f"control BatchGetItem returned {control_batch['Responses'][table]!r}"
    )

    # Query on the base table: projects to exactly the named set, and the List/Map attributes
    # come back whole -- there is no way to name an element inside them.
    key_conditions = {
        "pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"},
        "sk": {"AttributeValueList": [{"S": "s1"}], "ComparisonOperator": "EQ"},
    }
    queried = ddb.query(TableName=table, KeyConditions=key_conditions,
                        AttributesToGet=["name", "tags", "meta"], ConsistentRead=True)
    assert queried["Items"] == [{"name": {"S": "alpha"}, "tags": tags_list, "meta": meta_map}], (
        f"Query with AttributesToGet=[name,tags,meta] returned {queried['Items']!r}"
    )

    # Scan: the same projection and wholeness rule, read off the whole table rather than a key.
    scanned = ddb.scan(TableName=table, AttributesToGet=["name", "tags", "meta"], ConsistentRead=True)
    assert scanned["Count"] == 1, f"expected the single seeded item, got Count={scanned['Count']!r}"
    assert scanned["Items"] == [{"name": {"S": "alpha"}, "tags": tags_list, "meta": meta_map}], (
        f"Scan with AttributesToGet=[name,tags,meta] returned {scanned['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
