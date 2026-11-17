"""scan-filter-legacy-set-equality-eq-ne-on-ss-ns-bs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-legacy-set-equality-eq-ne-on-ss-ns-bs"
GROUP = "scan"
SERVICES = ["dynamodb"]


def _scan_sks(ddb, table, attr, filt) -> set:
    resp = ddb.scan(TableName=table, ScanFilter={attr: filt}, ConsistentRead=True)
    return {item["sk"]["S"] for item in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter EQ on SS/NS/BS matches only the item whose set holds exactly the
    same members regardless of order; NE matches every other item, including one missing it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-legsetfilt-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    pk = "p1"
    rows = {
        "exact_ss": {"ssattr": {"SS": ["b", "a"]}},
        "subset_ss": {"ssattr": {"SS": ["a"]}},
        "superset_ss": {"ssattr": {"SS": ["a", "b", "c"]}},
        "exact_ns": {"nsattr": {"NS": ["2", "1"]}},
        "subset_ns": {"nsattr": {"NS": ["1"]}},
        "superset_ns": {"nsattr": {"NS": ["1", "2", "3"]}},
        "exact_bs": {"bsattr": {"BS": [b"y", b"x"]}},
        "subset_bs": {"bsattr": {"BS": [b"x"]}},
        "superset_bs": {"bsattr": {"BS": [b"x", b"y", b"z"]}},
        "missing_all": {},
    }
    for sk, attrs in rows.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "sk": {"S": sk}, **attrs})
    all_sks = set(rows)

    cases = (
        ("ssattr", {"SS": ["a", "b"]}, "exact_ss"),
        ("nsattr", {"NS": ["1", "2"]}, "exact_ns"),
        ("bsattr", {"BS": [b"x", b"y"]}, "exact_bs"),
    )

    for attr, eq_value, exact_sk in cases:
        eq_matched = _scan_sks(ddb, table, attr, {"ComparisonOperator": "EQ", "AttributeValueList": [eq_value]})
        assert eq_matched == {exact_sk}, (
            f"ScanFilter {attr} EQ matched {sorted(eq_matched)!r}, expected only {{{exact_sk!r}}} "
            f"(member order, a subset and a superset must not match)"
        )

        ne_matched = _scan_sks(ddb, table, attr, {"ComparisonOperator": "NE", "AttributeValueList": [eq_value]})
        assert ne_matched == all_sks - {exact_sk}, (
            f"ScanFilter {attr} NE matched {sorted(ne_matched)!r}, expected the exact complement "
            f"{sorted(all_sks - {exact_sk})!r} (including the item missing {attr!r})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
