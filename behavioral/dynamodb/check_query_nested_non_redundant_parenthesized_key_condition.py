"""query-nested-non-redundant-parenthesized-key-condition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-nested-non-redundant-parenthesized-key-condition"
GROUP = "access_path"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KeyConditionExpression whose parentheses nest around a sub-clause, rather than
    wrapping the whole expression once, is accepted and evaluated correctly.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
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
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(3):
        ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": f"s{i}"}})

    # The inner paren wraps only the sort-key clause; the outer paren wraps the whole
    # AND, so the two parens enclose different, non-identical sub-expressions.
    resp = ddb.query(
        TableName=t,
        KeyConditionExpression="(pk = :p AND (sk = :s))",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":s": {"S": "s1"}},
        ConsistentRead=True,
    )
    assert resp["Count"] == 1, f"expected exactly 1 item, got {resp['Count']}"
    assert resp["Items"][0]["sk"] == {"S": "s1"}, f"expected sk=s1, got {resp['Items'][0].get('sk')}"

    # A second nesting shape: the inner paren wraps only the partition-key clause.
    resp2 = ddb.query(
        TableName=t,
        KeyConditionExpression="((pk = :p) AND sk BETWEEN :lo AND :hi)",
        ExpressionAttributeValues={
            ":p": {"S": "p1"}, ":lo": {"S": "s0"}, ":hi": {"S": "s1"},
        },
        ConsistentRead=True,
    )
    sks = sorted(item["sk"]["S"] for item in resp2["Items"])
    assert sks == ["s0", "s1"], f"expected sk in [s0, s1], got {sks}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
