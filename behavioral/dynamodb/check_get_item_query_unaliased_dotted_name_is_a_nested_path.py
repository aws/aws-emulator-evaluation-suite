"""get-item-query-unaliased-dotted-name-is-a-nested-path."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-item-query-unaliased-dotted-name-is-a-nested-path"
GROUP = "legacy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unaliased dot in GetItem/Query's ProjectionExpression is a nested path: it misses a
    top-level attribute literally named with that dot, which only an alias reaches. Legacy
    AttributesToGet names an attribute by its literal string and never splits on a dot.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbdot-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "rec1"}}
    flat_value = {"S": "flat-value"}
    meta_map = {"M": {"x": {"S": "nested-value"}, "y": {"S": "other"}}}
    ddb.put_item(TableName=table, Item={**key, "Safety.Warning": flat_value, "meta": meta_map})

    # Unaliased: the dot is parsed as a path separator, so it looks for a top-level "Safety"
    # holding a "Warning" member -- neither exists, so nothing is projected.
    unaliased = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                             ProjectionExpression="Safety.Warning")
    assert unaliased["Item"] == {}, (
        f"unaliased GetItem PE 'Safety.Warning' returned {unaliased['Item']!r}, expected an "
        f"empty Item because the dot is read as a nested path, not the flat attribute"
    )

    # Aliased: the placeholder's value is the literal dotted string, naming the flat attribute.
    aliased = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                           ProjectionExpression="#sw",
                           ExpressionAttributeNames={"#sw": "Safety.Warning"})
    assert aliased["Item"] == {"Safety.Warning": flat_value}, (
        f"aliased GetItem PE '#sw' returned {aliased['Item']!r}, expected the flat attribute "
        f"{{'Safety.Warning': {flat_value!r}}}"
    )

    # Legacy AttributesToGet never parses a path: a dotted name only matches a top-level
    # attribute spelled exactly that way, so it misses the nested meta.x leaf entirely.
    legacy_dotted = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                                 AttributesToGet=["meta.x"])
    assert legacy_dotted["Item"] == {}, (
        f"GetItem AttributesToGet=['meta.x'] returned {legacy_dotted['Item']!r}, expected an "
        f"empty Item -- 'meta.x' names a literal top-level attribute, not the meta.x leaf"
    )

    # Positive control: the same legacy parameter naming the whole top-level map.
    legacy_whole = ddb.get_item(TableName=table, Key=key, ConsistentRead=True,
                                AttributesToGet=["meta"])
    assert legacy_whole["Item"] == {"meta": meta_map}, (
        f"GetItem AttributesToGet=['meta'] returned {legacy_whole['Item']!r}, expected the "
        f"whole meta map {{'meta': {meta_map!r}}}"
    )

    # Query reproduces the same unaliased-vs-aliased split for the matched item.
    query_unaliased = ddb.query(TableName=table, ConsistentRead=True,
                                KeyConditionExpression="pk = :pk",
                                ExpressionAttributeValues={":pk": key["pk"]},
                                ProjectionExpression="Safety.Warning")
    assert (query_unaliased["Count"], query_unaliased["Items"]) == (1, [{}]), (
        f"Query with unaliased PE 'Safety.Warning' returned Count={query_unaliased['Count']!r} "
        f"Items={query_unaliased['Items']!r}, expected the matched item projected to {{}}"
    )

    query_aliased = ddb.query(TableName=table, ConsistentRead=True,
                              KeyConditionExpression="pk = :pk",
                              ExpressionAttributeValues={":pk": key["pk"]},
                              ProjectionExpression="#sw",
                              ExpressionAttributeNames={"#sw": "Safety.Warning"})
    assert (query_aliased["Count"], query_aliased["Items"]) == (1, [{"Safety.Warning": flat_value}]), (
        f"Query with aliased PE '#sw' returned Count={query_aliased['Count']!r} "
        f"Items={query_aliased['Items']!r}, expected the flat attribute on the matched item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
