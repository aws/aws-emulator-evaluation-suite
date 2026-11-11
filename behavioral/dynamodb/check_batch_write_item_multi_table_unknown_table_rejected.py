"""batch-write-item-multi-table-unknown-table-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-multi-table-unknown-table-rejected"
GROUP = "batch"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchWriteItem whose RequestItems map names one real table and one syntactically valid but
    nonexistent table is ResourceNotFoundException for the whole call; the real table gets no write.
    """
    ddb = ctx.client("dynamodb")
    real_table = ctx.unique_name("sim2real-behav-bwiunk-")
    missing_table = ctx.unique_name("sim2real-behav-bwiunk-missing-")
    ddb.create_table(
        TableName=real_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real_table))
    ddb.get_waiter("table_exists").wait(TableName=real_table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: BatchWriteItem over the real table alone works, so the rejection below is
    # attributable to the missing table and not to a broken request.
    control = ddb.batch_write_item(
        RequestItems={
            real_table: [{"PutRequest": {"Item": {"pk": {"S": "control"}, "v": {"S": "kept"}}}}],
        },
    )
    assert control.get("UnprocessedItems", {}) == {}, (
        f"positive control BatchWriteItem on the real table alone left unprocessed items: "
        f"{control.get('UnprocessedItems')!r}"
    )

    code, message = _error(lambda: ddb.batch_write_item(RequestItems={
        real_table: [{"PutRequest": {"Item": {"pk": {"S": "new"}, "v": {"S": "should-not-land"}}}}],
        missing_table: [{"PutRequest": {"Item": {"pk": {"S": "x"}, "v": {"S": "y"}}}}],
    }))
    assert code == "ResourceNotFoundException", (
        f"BatchWriteItem naming one real table and one nonexistent table must fail with "
        f"ResourceNotFoundException for the whole call, got {code!r}: {message!r}"
    )
    assert message == "Requested resource not found", f"unexpected message {message!r}"

    after = ddb.get_item(TableName=real_table, Key={"pk": {"S": "new"}}, ConsistentRead=True)
    assert "Item" not in after, (
        f"the refused BatchWriteItem must not have written to the real table, got {after.get('Item')!r}"
    )
    control_item = ddb.get_item(
        TableName=real_table, Key={"pk": {"S": "control"}}, ConsistentRead=True
    ).get("Item")
    assert control_item == {"pk": {"S": "control"}, "v": {"S": "kept"}}, (
        f"the real table's prior item must survive the refused call, got {control_item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
