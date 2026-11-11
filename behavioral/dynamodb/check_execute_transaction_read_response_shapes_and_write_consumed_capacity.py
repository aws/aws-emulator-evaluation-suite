"""execute-transaction-read-response-shapes-and-write-consumed-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "execute-transaction-read-response-shapes-and-write-consumed-capacity"
GROUP = "partiql"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteTransaction's Responses entries are a full item, an empty Item, or no Item key
    for a hit, a hit missing the projected attribute, and a miss, respectively. A write
    transaction returns an empty Responses list and one ConsumedCapacity entry per table.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteTransaction.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "attr": {"S": "v1"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s2"}})

    read = ddb.execute_transaction(TransactStatements=[
        {"Statement": f"""SELECT attr FROM "{t}" WHERE pk='p1' AND sk='s1'"""},
        {"Statement": f"""SELECT attr FROM "{t}" WHERE pk='p1' AND sk='s2'"""},
        {"Statement": f"""SELECT attr FROM "{t}" WHERE pk='p1' AND sk='s3'"""},
    ])
    responses = read["Responses"]
    assert responses == [{"Item": {"attr": {"S": "v1"}}}, {"Item": {}}, {}], (
        f"expected [hit, exists-without-attr, absent] shapes, got {responses!r}"
    )

    write = ddb.execute_transaction(
        TransactStatements=[
            {
                "Statement": f'UPDATE "{t}" SET other = ? WHERE pk = ? AND sk = ?',
                "Parameters": [{"S": "touched"}, {"S": "p1"}, {"S": "s1"}],
            },
            {
                "Statement": f'UPDATE "{t}" SET other = ? WHERE pk = ? AND sk = ?',
                "Parameters": [{"S": "touched"}, {"S": "p1"}, {"S": "s2"}],
            },
        ],
        ReturnConsumedCapacity="TOTAL",
    )
    assert write["Responses"] == [], (
        f"expected an empty Responses list for a write transaction, got {write['Responses']!r}"
    )
    consumed = write["ConsumedCapacity"]
    assert len(consumed) == 1, f"expected exactly one ConsumedCapacity entry, got {consumed!r}"
    assert consumed[0].get("TableName") == t, f"expected the entry to name the table, got {consumed[0]!r}"

    after_1 = ddb.get_item(TableName=t, Key={"pk": {"S": "p1"}, "sk": {"S": "s1"}}, ConsistentRead=True)["Item"]
    after_2 = ddb.get_item(TableName=t, Key={"pk": {"S": "p1"}, "sk": {"S": "s2"}}, ConsistentRead=True)["Item"]
    assert after_1.get("other") == {"S": "touched"}, f"expected the write transaction to have applied, got {after_1!r}"
    assert after_2.get("other") == {"S": "touched"}, f"expected the write transaction to have applied, got {after_2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
