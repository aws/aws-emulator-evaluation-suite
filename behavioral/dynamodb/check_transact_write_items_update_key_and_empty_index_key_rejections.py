"""transact-write-items-update-key-and-empty-index-key-rejections."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-update-key-and-empty-index-key-rejections"
GROUP = "transactions"
SERVICES = ["dynamodb"]


def _raises(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return exc
    raise AssertionError(f"{what}: the call was ACCEPTED; real AWS rejects it")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """A TransactWriteItems Update that SETs a key attribute is a cancellation, carrying a
    ValidationError cancellation reason; one that SETs a GSI key attribute to an empty string is
    up-front validation instead, a top-level ValidationException. Neither writes anything.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)
    pk, sk, gpk = ctx.unique_name("item-"), "s1", "g1"
    original = {"pk": {"S": pk}, "sk": {"S": sk}, "gpk": {"S": gpk}, "val": {"N": "1"}}
    ddb.put_item(TableName=table, Item=original)

    key_exc = _raises(
        lambda: ddb.transact_write_items(TransactItems=[{"Update": {
            "TableName": table,
            "Key": {"pk": {"S": pk}, "sk": {"S": sk}},
            "UpdateExpression": "SET pk = :v",
            "ExpressionAttributeValues": {":v": {"S": "other"}},
        }}]),
        "an Update whose UpdateExpression SETs the hash key attribute",
    )
    key_err = getattr(key_exc, "response", {}).get("Error", {}) or {}
    assert key_err.get("Code") == "TransactionCanceledException", (
        f"updating a key attribute: expected TransactionCanceledException, got {key_err.get('Code')!r}"
    )
    key_reasons = getattr(key_exc, "response", {}).get("CancellationReasons", [])
    assert len(key_reasons) == 1, f"expected exactly one cancellation reason, got {key_reasons!r}"
    assert key_reasons[0].get("Code") == "ValidationError", (
        f"updating a key attribute: expected cancellation reason ValidationError, got {key_reasons[0]!r}"
    )
    expected_key_message = (
        "One or more parameter values were invalid: Cannot update attribute pk. "
        "This attribute is part of the key"
    )
    assert key_reasons[0].get("Message") == expected_key_message, (
        f"updating a key attribute gave reason message {key_reasons[0].get('Message')!r}, "
        f"expected {expected_key_message!r}"
    )

    index_exc = _raises(
        lambda: ddb.transact_write_items(TransactItems=[{"Update": {
            "TableName": table,
            "Key": {"pk": {"S": pk}, "sk": {"S": sk}},
            "UpdateExpression": "SET gpk = :e",
            "ExpressionAttributeValues": {":e": {"S": ""}},
        }}]),
        "an Update whose UpdateExpression SETs a GSI key attribute to an empty string",
    )
    index_err = getattr(index_exc, "response", {}).get("Error", {}) or {}
    assert type(index_exc).__name__ != "TransactionCanceledException", (
        f"an empty index key is up-front validation, not a cancellation; got {type(index_exc).__name__}"
    )
    assert index_err.get("Code") == "ValidationException", (
        f"empty GSI key via Update: expected ValidationException, got {index_err.get('Code')!r}"
    )
    expected_index_message = (
        "One or more parameter values are not valid. The update expression attempted to update a "
        "secondary index key to a value that is not supported. The AttributeValue for a key "
        "attribute cannot contain an empty string value."
    )
    assert index_err.get("Message") == expected_index_message, (
        f"empty GSI key via Update gave message {index_err.get('Message')!r}, expected {expected_index_message!r}"
    )

    got = ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}}, ConsistentRead=True)["Item"]
    assert got == original, f"a rejected transaction must write nothing; item is now {got!r}"


def _create_table(ctx) -> str:
    """A table with hash+range key and a GSI on gpk (S), projecting all attributes."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
