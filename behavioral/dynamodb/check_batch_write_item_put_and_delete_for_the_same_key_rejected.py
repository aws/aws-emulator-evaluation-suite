"""batch-write-item-put-and-delete-for-the-same-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-put-and-delete-for-the-same-key-rejected"
GROUP = "batch"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_DUP_MESSAGE = "Provided list of item keys contains duplicates"


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
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem rejects a single call that pairs a PutRequest and a DeleteRequest on the
    SAME primary key with ValidationException, and applies neither that write nor any other,
    unrelated write in the same call.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchWriteItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-bwpd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # Positive control: a batch with no repeated key applies its writes, so the rejection below
    # is attributable to the repeated key, not to a broken client.
    ddb.batch_write_item(
        RequestItems={table: [{"PutRequest": {"Item": {"pk": {"S": "control"}, "v": {"N": "0"}}}}]}
    )
    control_after = ddb.get_item(TableName=table, Key={"pk": {"S": "control"}}, ConsistentRead=True)
    assert control_after.get("Item", {}).get("v") == {"N": "0"}, (
        f"positive control: a batch with no repeated key must apply its write, got {control_after}"
    )

    # A pre-existing item under the contested key, so a wrongly-accepted DeleteRequest would be
    # visible as a loss rather than a no-op on an absent key.
    shared_key = {"S": "shared-target"}
    ddb.put_item(TableName=table, Item={"pk": shared_key, "v": {"N": "1"}})

    code, message = _error(
        lambda: ddb.batch_write_item(
            RequestItems={
                table: [
                    {"PutRequest": {"Item": {"pk": shared_key, "v": {"N": "2"}}}},
                    {"DeleteRequest": {"Key": {"pk": shared_key}}},
                    {"PutRequest": {"Item": {"pk": {"S": "unrelated"}, "v": {"N": "3"}}}},
                ]
            }
        )
    )
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code}: {message!r}"
    assert message == _DUP_MESSAGE, f"expected the duplicate-keys refusal message, got {message!r}"

    shared_after = ddb.get_item(TableName=table, Key={"pk": shared_key}, ConsistentRead=True)
    assert shared_after.get("Item", {}).get("v") == {"N": "1"}, (
        f"a rejected mixed Put/Delete batch on one key must leave it exactly as seeded, got "
        f"{shared_after.get('Item')!r}"
    )
    unrelated_after = ddb.get_item(TableName=table, Key={"pk": {"S": "unrelated"}}, ConsistentRead=True)
    assert "Item" not in unrelated_after, (
        f"a rejected batch must apply NONE of its writes, including unrelated ones, got "
        f"{unrelated_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
