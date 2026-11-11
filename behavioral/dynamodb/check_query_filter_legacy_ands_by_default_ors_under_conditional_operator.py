"""query-filter-legacy-ands-by-default-ors-under-conditional-operator."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-legacy-ands-by-default-ors-under-conditional-operator"
GROUP = "query"
SERVICES = ["dynamodb"]

_ROWS = (
    {"sk": "s0", "plan": "gold", "points": 10},
    {"sk": "s1", "plan": "gold", "points": 50},
    {"sk": "s2", "plan": "silver", "points": 50},
    {"sk": "s3", "plan": "bronze", "points": 5},
)

_AND_MATCH = tuple(sorted(r["sk"] for r in _ROWS if r["plan"] == "gold" and r["points"] > 20))
_OR_MATCH = tuple(sorted(r["sk"] for r in _ROWS if r["plan"] == "gold" or r["points"] > 20))

_FILTER = {
    "plan": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "gold"}]},
    "points": {"ComparisonOperator": "GT", "AttributeValueList": [{"N": "20"}]},
}


def _ids(resp: dict) -> tuple:
    return tuple(sorted(i["sk"]["S"] for i in resp["Items"]))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's legacy QueryFilter with two conditions ANDs them when ConditionalOperator is
    omitted, and ORs them when ConditionalOperator is OR, over the whole scanned partition."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for row in _ROWS:
        ddb.put_item(TableName=t, Item={
            "pk": {"S": "p1"}, "sk": {"S": row["sk"]},
            "plan": {"S": row["plan"]}, "points": {"N": str(row["points"])},
        })

    default = ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter=_FILTER, ConsistentRead=True,
    )
    assert _ids(default) == _AND_MATCH, (
        f"omitting ConditionalOperator returned {_ids(default)!r}, expected the AND default "
        f"{_AND_MATCH!r}"
    )
    assert default["ScannedCount"] == len(_ROWS), (
        f"the default-AND query scanned {default['ScannedCount']!r}, expected the whole "
        f"partition of {len(_ROWS)}"
    )

    explicit_and = ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter=_FILTER, ConditionalOperator="AND", ConsistentRead=True,
    )
    assert _ids(explicit_and) == _AND_MATCH, (
        f"ConditionalOperator=AND returned {_ids(explicit_and)!r}, expected {_AND_MATCH!r} -- "
        f"the same as the default"
    )

    ored = ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter=_FILTER, ConditionalOperator="OR", ConsistentRead=True,
    )
    assert _ids(ored) == _OR_MATCH, (
        f"ConditionalOperator=OR returned {_ids(ored)!r}, expected the union {_OR_MATCH!r}"
    )
    assert ored["ScannedCount"] == len(_ROWS), (
        f"the OR query scanned {ored['ScannedCount']!r}, expected the whole partition of "
        f"{len(_ROWS)}"
    )
    assert _OR_MATCH != _AND_MATCH, (
        "the OR and AND unions coincide, so this scenario does not distinguish them"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
