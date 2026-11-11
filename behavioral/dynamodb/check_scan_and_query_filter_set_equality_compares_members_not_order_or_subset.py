"""scan-and-query-filter-set-equality-compares-members-not-order-or-subset."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-and-query-filter-set-equality-compares-members-not-order-or-subset"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _scan(ddb, table, filter_expr, values):
    resp = ddb.scan(
        TableName=table,
        FilterExpression=filter_expr,
        ExpressionAttributeValues=values,
        ConsistentRead=True,
    )
    return {item["sk"]["S"] for item in resp["Items"]}


def _query(ddb, table, pk, filter_expr, values):
    resp = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :pk",
        FilterExpression=filter_expr,
        ExpressionAttributeValues={**values, ":pk": {"S": pk}},
        ConsistentRead=True,
    )
    return {item["sk"]["S"] for item in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterExpression '=' on an SS/NS/BS attribute matches only the item whose set holds
    exactly the value's members, regardless of order; a subset or superset does not match,
    and '<>' returns every other item, including one missing the attribute.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-setfilt-")
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

    ss_eq = {":v": {"SS": ["a", "b"]}}
    ns_eq = {":v": {"NS": ["1", "2"]}}
    bs_eq = {":v": {"BS": [b"x", b"y"]}}

    for attr, eq_values, exact_sk in (
        ("ssattr", ss_eq, "exact_ss"),
        ("nsattr", ns_eq, "exact_ns"),
        ("bsattr", bs_eq, "exact_bs"),
    ):
        matched = _scan(ddb, table, f"{attr} = :v", eq_values)
        assert matched == {exact_sk}, (
            f"Scan '{attr} = :v' matched {sorted(matched)!r}, expected only {{{exact_sk!r}}} "
            f"(member order, a subset and a superset must not match)"
        )
        complement = _scan(ddb, table, f"{attr} <> :v", eq_values)
        assert complement == all_sks - {exact_sk}, (
            f"Scan '{attr} <> :v' matched {sorted(complement)!r}, expected the exact complement "
            f"{sorted(all_sks - {exact_sk})!r} (including the item missing {attr!r})"
        )

    # Query leg on the same partition: the same '=' and '<>' set semantics hold under a
    # FilterExpression applied after the key condition narrows to one partition.
    q_matched = _query(ddb, table, pk, "ssattr = :v", ss_eq)
    assert q_matched == {"exact_ss"}, (
        f"Query 'ssattr = :v' matched {sorted(q_matched)!r}, expected only {{'exact_ss'}}"
    )
    q_complement = _query(ddb, table, pk, "ssattr <> :v", ss_eq)
    assert q_complement == all_sks - {"exact_ss"}, (
        f"Query 'ssattr <> :v' matched {sorted(q_complement)!r}, expected the exact complement "
        f"{sorted(all_sks - {'exact_ss'})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
