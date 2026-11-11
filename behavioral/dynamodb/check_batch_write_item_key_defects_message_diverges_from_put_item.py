"""batch-write-item-key-defects-message-diverges-from-put-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-key-defects-message-diverges-from-put-item"
GROUP = 'negative-classes'
SERVICES = ['dynamodb']


def _error_code_and_message(fn):
    """Call fn(); return the botocore Error.Code and Error.Message. An unexpected SUCCESS
    raises instead of returning a falsy code, because an emulator ACCEPTING input real AWS
    refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem's PutRequest and DeleteRequest reject a wrong-typed, list-typed or missing
    partition key with ValidationException and one fixed message, which differs from PutItem's
    defect-specific message for the same malformed item; nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchWriteItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))

    batch_generic_message = "The provided key element does not match the schema"

    defects = [
        ("wrong-typed", {"pk": {"N": "1"}}, "Type mismatch for key pk expected: S actual: N"),
        ("list-typed", {"pk": {"L": [{"S": "x"}]}}, "Type mismatch for key pk expected: S actual: L"),
        ("missing", {"other": {"S": "x"}}, "Missing the key pk in the item"),
    ]

    for label, malformed_key_or_item, put_item_suffix in defects:
        put_code, put_message = _error_code_and_message(
            lambda m=malformed_key_or_item: ddb.put_item(TableName=table, Item=dict(m))
        )
        assert put_code == "ValidationException", (
            f"PutItem {label} partition key: expected ValidationException, got {put_code!r}"
        )
        expected_put_message = f"One or more parameter values were invalid: {put_item_suffix}"
        assert put_message == expected_put_message, (
            f"PutItem {label} partition key: expected message {expected_put_message!r}, "
            f"got {put_message!r}"
        )

        batch_put_code, batch_put_message = _error_code_and_message(
            lambda m=malformed_key_or_item: ddb.batch_write_item(
                RequestItems={table: [{"PutRequest": {"Item": dict(m)}}]}
            )
        )
        assert batch_put_code == "ValidationException", (
            f"BatchWriteItem PutRequest {label} partition key: expected ValidationException, "
            f"got {batch_put_code!r}"
        )
        assert batch_put_message == batch_generic_message, (
            f"BatchWriteItem PutRequest {label} partition key: expected message "
            f"{batch_generic_message!r}, got {batch_put_message!r}"
        )
        assert batch_put_message != put_message, (
            f"BatchWriteItem PutRequest {label} partition key: message {batch_put_message!r} "
            f"must diverge from PutItem's defect-specific message {put_message!r}, not reuse it"
        )

        batch_delete_code, batch_delete_message = _error_code_and_message(
            lambda m=malformed_key_or_item: ddb.batch_write_item(
                RequestItems={table: [{"DeleteRequest": {"Key": dict(m)}}]}
            )
        )
        assert batch_delete_code == "ValidationException", (
            f"BatchWriteItem DeleteRequest {label} partition key: expected ValidationException, "
            f"got {batch_delete_code!r}"
        )
        assert batch_delete_message == batch_generic_message, (
            f"BatchWriteItem DeleteRequest {label} partition key: expected message "
            f"{batch_generic_message!r}, got {batch_delete_message!r}"
        )
        assert batch_delete_message != put_message, (
            f"BatchWriteItem DeleteRequest {label} partition key: message "
            f"{batch_delete_message!r} must diverge from PutItem's defect-specific message "
            f"{put_message!r}, not reuse it"
        )

    # Effect absent: none of the six rejected calls above wrote anything.
    scan = ddb.scan(TableName=table, ConsistentRead=True)
    assert scan["Count"] == 0, f"rejected calls must leave the table empty, found {scan['Count']} item(s)"

    # Positive control: a correctly-typed PutItem and a correctly-typed BatchWriteItem
    # PutRequest both succeed on the same table.
    good_pk_1 = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": good_pk_1}, "note": {"S": "good-put"}})
    got_1 = ddb.get_item(TableName=table, Key={"pk": {"S": good_pk_1}}, ConsistentRead=True)
    assert got_1.get("Item") is not None, "positive control PutItem did not persist"
    assert got_1["Item"]["note"]["S"] == "good-put", (
        f"expected note='good-put', got {got_1['Item']['note']['S']!r}"
    )

    good_pk_2 = ctx.unique_name("item-")
    ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {"pk": {"S": good_pk_2}, "note": {"S": "good-batch"}}}}
    ]})
    got_2 = ddb.get_item(TableName=table, Key={"pk": {"S": good_pk_2}}, ConsistentRead=True)
    assert got_2.get("Item") is not None, "positive control BatchWriteItem PutRequest did not persist"
    assert got_2["Item"]["note"]["S"] == "good-batch", (
        f"expected note='good-batch', got {got_2['Item']['note']['S']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
