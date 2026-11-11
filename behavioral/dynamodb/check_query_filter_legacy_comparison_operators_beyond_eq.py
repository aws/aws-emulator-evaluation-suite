"""query-filter-legacy-comparison-operators-beyond-eq."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-legacy-comparison-operators-beyond-eq"
GROUP = "query"
SERVICES = ["dynamodb"]

# label: string substring target; code: numeric NE target; points: numeric GT/BETWEEN target
# chosen so a lexicographic compare disagrees with a numeric one (9 < 10 < 11 < 100 < 200
# numerically, but "100" < "11" < "200" < "9" as strings); plan: IN target; enabled: BOOL target;
# memo: present on some rows only, for NULL/NOT_NULL.
_ROWS = (
    {"sk": "s0", "label": "catalog", "code": 1, "points": 8, "plan": "gold", "enabled": True, "memo": "a"},
    {"sk": "s1", "label": "banana", "code": 2, "points": 9, "plan": "silver", "enabled": False, "memo": "b"},
    {"sk": "s2", "label": "category", "code": 1, "points": 10, "plan": "bronze", "enabled": True},
    {"sk": "s3", "label": "dog", "code": 3, "points": 11, "plan": "gold", "enabled": False},
    {"sk": "s4", "label": "cathedral", "code": 1, "points": 100, "plan": "platinum", "enabled": True, "memo": "c"},
)

_CONTAINS = tuple(sorted(r["sk"] for r in _ROWS if "cat" in r["label"]))
_NE = tuple(sorted(r["sk"] for r in _ROWS if r["code"] != 1))
_GT = tuple(sorted(r["sk"] for r in _ROWS if r["points"] > 9))
_BETWEEN = tuple(sorted(r["sk"] for r in _ROWS if 9 <= r["points"] <= 11))
_IN = tuple(sorted(r["sk"] for r in _ROWS if r["plan"] in ("gold", "silver")))
_BOOL_EQ = tuple(sorted(r["sk"] for r in _ROWS if r["enabled"] is True))
_NULL = tuple(sorted(r["sk"] for r in _ROWS if "memo" not in r))
_NOT_NULL = tuple(sorted(r["sk"] for r in _ROWS if "memo" in r))


def _item(row: dict) -> dict:
    out = {
        "pk": {"S": "p1"}, "sk": {"S": row["sk"]}, "label": {"S": row["label"]},
        "code": {"N": str(row["code"])}, "points": {"N": str(row["points"])},
        "plan": {"S": row["plan"]}, "enabled": {"BOOL": row["enabled"]},
    }
    if "memo" in row:
        out["memo"] = {"S": row["memo"]}
    return out


def _ids(resp: dict) -> tuple:
    return tuple(sorted(i["sk"]["S"] for i in resp["Items"]))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's legacy QueryFilter evaluates CONTAINS, NE, GT, BETWEEN (N numerically), IN, BOOL
    EQ, NULL and NOT_NULL exactly as their FilterExpression twin, over the whole partition, and
    without lowering ConsumedCapacity relative to an unfiltered Query."""
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
        ddb.put_item(TableName=t, Item=_item(row))

    base = ddb.query(
        TableName=t, KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": "pk"}, ExpressionAttributeValues={":pk": {"S": "p1"}},
        ConsistentRead=True, ReturnConsumedCapacity="TOTAL",
    )
    assert base["Count"] == len(_ROWS) and base["ScannedCount"] == len(_ROWS), (
        f"unfiltered baseline must see every seeded item, got Count={base['Count']!r} "
        f"ScannedCount={base['ScannedCount']!r} over {len(_ROWS)} seeded"
    )
    baseline_cu = base["ConsumedCapacity"]["CapacityUnits"]

    def _legacy(query_filter: dict) -> dict:
        return ddb.query(
            TableName=t,
            KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
            QueryFilter=query_filter, ConsistentRead=True, ReturnConsumedCapacity="TOTAL",
        )

    def _expr(filter_expression: str, names: dict, values: dict) -> dict:
        return ddb.query(
            TableName=t, KeyConditionExpression="#pk = :pk", FilterExpression=filter_expression,
            ExpressionAttributeNames={"#pk": "pk", **names},
            ExpressionAttributeValues={":pk": {"S": "p1"}, **values},
            ConsistentRead=True, ReturnConsumedCapacity="TOTAL",
        )

    def _assert_twin(op: str, legacy_resp: dict, expr_resp: dict, expected: tuple) -> None:
        assert _ids(legacy_resp) == expected, (
            f"{op}: legacy QueryFilter returned {_ids(legacy_resp)!r}, expected {expected!r}"
        )
        assert _ids(expr_resp) == expected, (
            f"{op}: FilterExpression twin returned {_ids(expr_resp)!r}, expected {expected!r}"
        )
        assert legacy_resp["Count"] == expr_resp["Count"] == len(expected), (
            f"{op}: legacy Count={legacy_resp['Count']!r}, twin Count={expr_resp['Count']!r}, "
            f"expected {len(expected)!r}"
        )
        assert legacy_resp["ScannedCount"] == len(_ROWS), (
            f"{op}: QueryFilter must scan the whole partition, got "
            f"ScannedCount={legacy_resp['ScannedCount']!r}, expected {len(_ROWS)}"
        )
        got_cu = legacy_resp["ConsumedCapacity"]["CapacityUnits"]
        assert got_cu == baseline_cu, (
            f"{op}: QueryFilter changed ConsumedCapacity to {got_cu!r}, baseline was {baseline_cu!r}"
        )

    _assert_twin(
        "CONTAINS",
        _legacy({"label": {"ComparisonOperator": "CONTAINS", "AttributeValueList": [{"S": "cat"}]}}),
        _expr("contains(#lbl, :v)", {"#lbl": "label"}, {":v": {"S": "cat"}}),
        _CONTAINS,
    )
    _assert_twin(
        "NE",
        _legacy({"code": {"ComparisonOperator": "NE", "AttributeValueList": [{"N": "1"}]}}),
        _expr("#cod <> :v", {"#cod": "code"}, {":v": {"N": "1"}}),
        _NE,
    )
    _assert_twin(
        "GT",
        _legacy({"points": {"ComparisonOperator": "GT", "AttributeValueList": [{"N": "9"}]}}),
        _expr("#pts > :v", {"#pts": "points"}, {":v": {"N": "9"}}),
        _GT,
    )
    _assert_twin(
        "BETWEEN",
        _legacy({"points": {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"N": "9"}, {"N": "11"}]}}),
        _expr("#pts BETWEEN :lo AND :hi", {"#pts": "points"}, {":lo": {"N": "9"}, ":hi": {"N": "11"}}),
        _BETWEEN,
    )
    _assert_twin(
        "IN",
        _legacy({"plan": {"ComparisonOperator": "IN", "AttributeValueList": [{"S": "gold"}, {"S": "silver"}]}}),
        _expr("#pln IN (:a, :b)", {"#pln": "plan"}, {":a": {"S": "gold"}, ":b": {"S": "silver"}}),
        _IN,
    )
    _assert_twin(
        "EQ-BOOL",
        _legacy({"enabled": {"ComparisonOperator": "EQ", "AttributeValueList": [{"BOOL": True}]}}),
        _expr("#en = :v", {"#en": "enabled"}, {":v": {"BOOL": True}}),
        _BOOL_EQ,
    )
    _assert_twin(
        "NULL",
        _legacy({"memo": {"ComparisonOperator": "NULL"}}),
        _expr("attribute_not_exists(#memo)", {"#memo": "memo"}, {}),
        _NULL,
    )
    _assert_twin(
        "NOT_NULL",
        _legacy({"memo": {"ComparisonOperator": "NOT_NULL"}}),
        _expr("attribute_exists(#memo)", {"#memo": "memo"}, {}),
        _NOT_NULL,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
