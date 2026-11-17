"""batch-write-item-aggregate-25-item-limit-spans-every-table-in-the-call."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-aggregate-25-item-limit-spans-every-table-in-the-call"
GROUP = "batch"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_AGGREGATE_MESSAGE = "Too many items requested for the BatchWriteItem call"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem's 25-request limit is counted across every table in the call: 13 + 12
    requests over two tables (25 total) is accepted whole, and 13 + 13 (26 total, neither table's
    own list over 25) is refused with a distinct aggregate-count message, writing neither table.
    """
    ddb = ctx.client("dynamodb")
    table_a = ctx.unique_name("sim2real-behav-ddbbw25-a-")
    ddb.create_table(
        TableName=table_a,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_a), "ResourceNotFoundException"))

    table_b = ctx.unique_name("sim2real-behav-ddbbw25-b-")
    ddb.create_table(
        TableName=table_b,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table_b), "ResourceNotFoundException"))

    ddb.get_waiter("table_exists").wait(TableName=table_a, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ddb.get_waiter("table_exists").wait(TableName=table_b, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # Positive control: 13 requests on table_a plus 12 on table_b is exactly 25 in total and is
    # accepted whole, so the rejection below is attributable to the aggregate count alone.
    control_a = [{"PutRequest": {"Item": {"pk": {"S": f"ok-a-{i}"}}}} for i in range(13)]
    control_b = [{"PutRequest": {"Item": {"pk": {"S": f"ok-b-{i}"}}}} for i in range(12)]
    control = ddb.batch_write_item(RequestItems={table_a: control_a, table_b: control_b})
    assert control.get("UnprocessedItems", {}) == {}, (
        f"a 13+12 (25 total) batch across two tables must be accepted whole, got "
        f"UnprocessedItems={control.get('UnprocessedItems')!r}"
    )
    assert ddb.get_item(TableName=table_a, Key={"pk": {"S": "ok-a-0"}}, ConsistentRead=True).get("Item") == (
        {"pk": {"S": "ok-a-0"}}
    ), "the control batch's item in table_a did not land"
    assert ddb.get_item(TableName=table_b, Key={"pk": {"S": "ok-b-0"}}, ConsistentRead=True).get("Item") == (
        {"pk": {"S": "ok-b-0"}}
    ), "the control batch's item in table_b did not land"

    # The subject: 13 + 13 = 26 requests, neither table's own list exceeding 25 on its own.
    over_a = [{"PutRequest": {"Item": {"pk": {"S": f"over-a-{i}"}}}} for i in range(13)]
    over_b = [{"PutRequest": {"Item": {"pk": {"S": f"over-b-{i}"}}}} for i in range(13)]
    code, message = _error(lambda: ddb.batch_write_item(RequestItems={table_a: over_a, table_b: over_b}))
    assert code == ERR_VALIDATION, (
        f"a 13+13 (26 total) batch across two tables must be refused with {ERR_VALIDATION}, "
        f"got {code!r}: {message!r}"
    )
    assert message == _AGGREGATE_MESSAGE, (
        f"expected the aggregate-count message {_AGGREGATE_MESSAGE!r}, got {message!r}"
    )

    assert ddb.get_item(TableName=table_a, Key={"pk": {"S": "over-a-0"}}, ConsistentRead=True).get("Item") is None, (
        "the refused 26-item batch must not have written to table_a"
    )
    assert ddb.get_item(TableName=table_b, Key={"pk": {"S": "over-b-0"}}, ConsistentRead=True).get("Item") is None, (
        "the refused 26-item batch must not have written to table_b"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
