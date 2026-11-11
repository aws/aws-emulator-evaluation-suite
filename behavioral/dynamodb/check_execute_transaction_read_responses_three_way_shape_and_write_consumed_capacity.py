"""execute-transaction-read-responses-three-way-shape-and-write-consumed-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "execute-transaction-read-responses-three-way-shape-and-write-consumed-capacity"
GROUP = "partiql"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A read-only ExecuteTransaction returns one Responses entry per SELECT, in order: {Item:
    {...}} found with the attribute, {Item: {}} found without it, {} when the key is absent. A
    write-only ExecuteTransaction returns Responses == [] and one ConsumedCapacity entry of 2 units per write.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "present"}, "attr": {"S": "hit"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "sparse"}})
    # sk "absent" is never written.

    def _select(sk: str) -> dict:
        return {
            "Statement": f'SELECT attr FROM "{table}" WHERE pk=? AND sk=?',
            "Parameters": [{"S": "p1"}, {"S": sk}],
        }

    read_resp = ddb.execute_transaction(
        TransactStatements=[_select("present"), _select("sparse"), _select("absent")]
    )
    responses = read_resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses!r}"
    assert responses[0] == {"Item": {"attr": {"S": "hit"}}}, (
        f"expected the existing item's projected attribute, got {responses[0]!r}"
    )
    assert responses[1] == {"Item": {}}, (
        f"expected an existing item lacking the projected attribute to answer an empty Item, got {responses[1]!r}"
    )
    assert responses[2] == {}, (
        f"expected a non-existent key to answer with no Item key at all, got {responses[2]!r}"
    )

    inserted_key = {"pk": {"S": "p1"}, "sk": {"S": "inserted"}}
    write_resp = ddb.execute_transaction(
        TransactStatements=[
            {
                "Statement": f'INSERT INTO "{table}" VALUE {{\'pk\': ?, \'sk\': ?}}',
                "Parameters": [{"S": "p1"}, {"S": "inserted"}],
            },
            {
                "Statement": f'DELETE FROM "{table}" WHERE pk=? AND sk=?',
                "Parameters": [{"S": "p1"}, {"S": "sparse"}],
            },
        ],
        ReturnConsumedCapacity="TOTAL",
    )
    assert write_resp["Responses"] == [], f"expected a write transaction to answer Responses == [], got {write_resp['Responses']!r}"
    consumed = write_resp["ConsumedCapacity"]
    assert len(consumed) == 1, f"expected exactly one ConsumedCapacity entry, got {len(consumed)}: {consumed!r}"
    assert consumed[0]["TableName"] == table, f"expected the ConsumedCapacity entry to name the table, got {consumed[0]!r}"
    assert consumed[0]["CapacityUnits"] == 4.0, (
        f"a transactional INSERT plus DELETE of two small items must bill 2.0 units each, 4.0 in all, "
        f"got {consumed[0]!r}"
    )

    # Prove the write transaction's effects with independent reads.
    inserted = ddb.get_item(TableName=table, Key=inserted_key, ConsistentRead=True)
    assert inserted.get("Item") == inserted_key, f"expected the INSERTed item to read back, got {inserted.get('Item')!r}"
    deleted = ddb.get_item(TableName=table, Key={"pk": {"S": "p1"}, "sk": {"S": "sparse"}}, ConsistentRead=True)
    assert "Item" not in deleted, f"expected the DELETEd item to be gone, got {deleted.get('Item')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
