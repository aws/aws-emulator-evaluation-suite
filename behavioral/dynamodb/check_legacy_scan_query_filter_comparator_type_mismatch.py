"""legacy-scan-query-filter-comparator-type-mismatch."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "legacy-scan-query-filter-comparator-type-mismatch"
GROUP = "scan"
SERVICES = ["dynamodb"]

# A legacy ScanFilter/QueryFilter ComparisonOperator condition whose AttributeValueList
# element is a different type than the stored attribute excludes every item for these
# comparators; NE includes every item instead, because the type mismatch alone satisfies
# "not equal".
_EXCLUDES_EVERY_ITEM = ("EQ", "LE", "LT", "GE", "GT")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy ScanFilter/QueryFilter comparator whose value type differs from the stored
    attribute's matches no item, except NE, which then matches every item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.Conditions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbtmf-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": "target"}, "num": {"N": "6"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": "other"}, "num": {"N": "99"}})
    both = ["other", "target"]

    def scan_ids(filt):
        resp = ddb.scan(TableName=table, ScanFilter={"num": filt}, ConsistentRead=True)
        return sorted(item["sk"]["S"] for item in resp["Items"])

    def query_ids(filt):
        resp = ddb.query(
            TableName=table,
            KeyConditions={"pk": {"AttributeValueList": [{"S": "p"}], "ComparisonOperator": "EQ"}},
            QueryFilter={"num": filt},
            ConsistentRead=True,
        )
        return sorted(item["sk"]["S"] for item in resp["Items"])

    for op in _EXCLUDES_EVERY_ITEM:
        filt = {"ComparisonOperator": op, "AttributeValueList": [{"S": "6"}]}
        scanned = scan_ids(filt)
        assert scanned == [], f"ScanFilter {op} with a type-mismatched value matched {scanned!r}, expected none"
        queried = query_ids(filt)
        assert queried == [], f"QueryFilter {op} with a type-mismatched value matched {queried!r}, expected none"

    between_filt = {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"S": "0"}, {"S": "9"}]}
    scanned = scan_ids(between_filt)
    assert scanned == [], f"ScanFilter BETWEEN with type-mismatched bounds matched {scanned!r}, expected none"
    queried = query_ids(between_filt)
    assert queried == [], f"QueryFilter BETWEEN with type-mismatched bounds matched {queried!r}, expected none"

    # NE: every item's type differs from the filter value's, so every item is "not equal"
    # and matches, including the item whose own value equals 6 numerically.
    ne_filt = {"ComparisonOperator": "NE", "AttributeValueList": [{"S": "6"}]}
    scanned = scan_ids(ne_filt)
    assert scanned == both, f"ScanFilter NE with a type-mismatched value matched {scanned!r}, expected both items"
    queried = query_ids(ne_filt)
    assert queried == both, f"QueryFilter NE with a type-mismatched value matched {queried!r}, expected both items"

    # A number compared against a number set of the same member follows the same rule.
    ns_eq = {"ComparisonOperator": "EQ", "AttributeValueList": [{"NS": ["6"]}]}
    scanned = scan_ids(ns_eq)
    assert scanned == [], f"ScanFilter EQ N-vs-NS matched {scanned!r}, expected none"
    ns_ne = {"ComparisonOperator": "NE", "AttributeValueList": [{"NS": ["6"]}]}
    scanned = scan_ids(ns_ne)
    assert scanned == both, f"ScanFilter NE N-vs-NS matched {scanned!r}, expected both items"

    # Positive control: the filtering mechanism itself discriminates on value, not just on
    # type -- a matched-type EQ returns only the item whose number actually equals 6.
    matched_filt = {"ComparisonOperator": "EQ", "AttributeValueList": [{"N": "6"}]}
    scanned = scan_ids(matched_filt)
    assert scanned == ["target"], f"positive control: ScanFilter EQ with a matched type returned {scanned!r}"
    queried = query_ids(matched_filt)
    assert queried == ["target"], f"positive control: QueryFilter EQ with a matched type returned {queried!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
