"""scan-filter-conditional-operator-default-matches-and-diverges-from-or."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-conditional-operator-default-matches-and-diverges-from-or"
GROUP = "scan"
SERVICES = ["dynamodb"]


def _seed(ctx, ddb, table: str) -> None:
    """Five rows where the GE-only and EQ-only ScanFilter conditions overlap on exactly
    one row, so their AND and OR compositions resolve to different, countable sets."""
    rows = (
        ("sku-widget", 50, "clearance"),
        ("sku-gadget", 150, "overstock"),
        ("sku-gizmo", 200, "clearance"),
        ("sku-doodad", 30, "overstock"),
        ("sku-trinket", 120, "seasonal"),
    )
    for sku, price, tag in rows:
        ddb.put_item(TableName=table, Item={
            "sku": {"S": sku}, "price": {"N": str(price)}, "tag": {"S": tag},
        })


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two legacy ScanFilter conditions are ANDed when ConditionalOperator is omitted,
    the same set as ConditionalOperator=AND, and a larger, different set under OR.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scfand-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "sku", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "sku", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _seed(ctx, ddb, table)

    price_cond = {"ComparisonOperator": "GE", "AttributeValueList": [{"N": "100"}]}
    tag_cond = {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "clearance"}]}

    def scan_skus(**kwargs) -> set:
        resp = ddb.scan(TableName=table, ConsistentRead=True, **kwargs)
        return {item["sku"]["S"] for item in resp["Items"]}

    price_only = scan_skus(ScanFilter={"price": price_cond})
    assert price_only == {"sku-gadget", "sku-gizmo", "sku-trinket"}, (
        f"price GE 100 alone matched {sorted(price_only)!r}, expected the three priced at or "
        f"above 100"
    )

    tag_only = scan_skus(ScanFilter={"tag": tag_cond})
    assert tag_only == {"sku-widget", "sku-gizmo"}, (
        f"tag EQ clearance alone matched {sorted(tag_only)!r}, expected the two tagged clearance"
    )

    both_filters = {"price": price_cond, "tag": tag_cond}
    expected_and = {"sku-gizmo"}
    expected_or = {"sku-widget", "sku-gadget", "sku-gizmo", "sku-trinket"}

    omitted = scan_skus(ScanFilter=both_filters)
    assert omitted == expected_and, (
        f"omitting ConditionalOperator matched {sorted(omitted)!r}, expected the AND "
        f"intersection {sorted(expected_and)!r}"
    )

    explicit_and = scan_skus(ScanFilter=both_filters, ConditionalOperator="AND")
    assert explicit_and == expected_and, (
        f"ConditionalOperator=AND matched {sorted(explicit_and)!r}, expected the same "
        f"intersection {sorted(expected_and)!r} the omitted form produced"
    )

    explicit_or = scan_skus(ScanFilter=both_filters, ConditionalOperator="OR")
    assert explicit_or == expected_or, (
        f"ConditionalOperator=OR matched {sorted(explicit_or)!r}, expected the union "
        f"{sorted(expected_or)!r}"
    )
    assert len(explicit_or) > len(expected_and), (
        f"the OR union {sorted(explicit_or)!r} is not larger than the AND intersection "
        f"{sorted(expected_and)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
