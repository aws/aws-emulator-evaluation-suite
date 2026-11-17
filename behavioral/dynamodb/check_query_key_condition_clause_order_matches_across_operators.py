"""query-key-condition-clause-order-matches-across-operators."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-key-condition-clause-order-matches-across-operators"
GROUP = "query"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query's KeyConditionExpression returns the identical ordered Items list whether the
    sort-key clause is written before or after the partition-key clause, for a '>=' comparator,
    BETWEEN and begins_with alike; ScanIndexForward=False reverses both orderings the same way.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-kcorder-")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    described = ddb.describe_table(TableName=table)["Table"]
    assert described["TableStatus"] == "ACTIVE", f"table {table!r} is {described['TableStatus']!r}, expected ACTIVE"
    assert described["KeySchema"] == [
        {"AttributeName": "pk", "KeyType": "HASH"},
        {"AttributeName": "sk", "KeyType": "RANGE"},
    ], f"DescribeTable reports key schema {described['KeySchema']!r}"

    for sk in ("a", "b0", "b1"):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": sk}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p2"}, "sk": {"S": "b0"}})

    want_asc = [
        {"pk": {"S": "p1"}, "sk": {"S": "b0"}},
        {"pk": {"S": "p1"}, "sk": {"S": "b1"}},
    ]
    want_desc = list(reversed(want_asc))

    def query(cond, values, *, forward):
        return ddb.query(
            TableName=table, KeyConditionExpression=cond,
            ExpressionAttributeValues=values, ScanIndexForward=forward, ConsistentRead=True,
        )["Items"]

    forms = (
        ("sk >= :s AND pk = :p", "pk = :p AND sk >= :s", {":p": {"S": "p1"}, ":s": {"S": "b0"}}),
        (
            "sk BETWEEN :lo AND :hi AND pk = :p", "pk = :p AND sk BETWEEN :lo AND :hi",
            {":p": {"S": "p1"}, ":lo": {"S": "b0"}, ":hi": {"S": "b1"}},
        ),
        (
            "begins_with(sk, :q) AND pk = :p", "pk = :p AND begins_with(sk, :q)",
            {":p": {"S": "p1"}, ":q": {"S": "b"}},
        ),
    )
    for sk_first, pk_first, values in forms:
        got_sk_first = query(sk_first, values, forward=True)
        got_pk_first = query(pk_first, values, forward=True)
        assert got_sk_first == want_asc, f"{sk_first!r} returned {got_sk_first!r}, expected {want_asc!r}"
        assert got_pk_first == want_asc, f"{pk_first!r} returned {got_pk_first!r}, expected {want_asc!r}"

        got_sk_first_desc = query(sk_first, values, forward=False)
        got_pk_first_desc = query(pk_first, values, forward=False)
        assert got_sk_first_desc == want_desc, (
            f"{sk_first!r} with ScanIndexForward=False returned {got_sk_first_desc!r}, expected {want_desc!r}"
        )
        assert got_pk_first_desc == want_desc, (
            f"{pk_first!r} with ScanIndexForward=False returned {got_pk_first_desc!r}, expected {want_desc!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
