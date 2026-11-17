"""batch-write-item-oversized-gsi-partition-key-value-rejected-whole."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-oversized-gsi-partition-key-value-rejected-whole"
GROUP = "capacity"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises on anything but not_found."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table: str, deadline: float) -> None:
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            i.get("IndexStatus") == "ACTIVE" for i in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} did not reach ACTIVE with its GSI before the deadline")


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
    """BatchWriteItem refuses the whole batch when one item's GSI partition key value is
    over the 2048-byte limit, and neither that item nor its well-formed sibling is written.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddboverk-")
    ddb.create_table(
        TableName=table,
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
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 900.0) - 60.0)
    _wait_active(ddb, table, deadline)

    # Positive control: a well-formed batch against this table and index succeeds, so a
    # rejection below is attributable to the oversized key and not to a broken setup.
    ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {"pk": {"S": "control"}, "sk": {"S": "1"}, "gpk": {"S": "g-control"}}}},
    ]})
    control = ddb.get_item(TableName=table, Key={"pk": {"S": "control"}, "sk": {"S": "1"}},
                           ConsistentRead=True)["Item"]
    assert control == {"pk": {"S": "control"}, "sk": {"S": "1"}, "gpk": {"S": "g-control"}}, (
        f"positive control did not round-trip: {control!r}"
    )

    oversized_gpk = "x" * 2049
    code, message = _error(lambda: ddb.batch_write_item(RequestItems={table: [
        {"PutRequest": {"Item": {"pk": {"S": "valid"}, "sk": {"S": "1"}, "gpk": {"S": "g-valid"}}}},
        {"PutRequest": {"Item": {"pk": {"S": "bad"}, "sk": {"S": "1"}, "gpk": {"S": oversized_gpk}}}},
    ]}))
    assert code == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code}: {message!r}"
    expected_message = (
        "One or more parameter values were invalid: Size limit exceeded for Index Key gpk "
        "Actual Size: 2049 bytes Max Size: 2048 bytes IndexName: gsi1"
    )
    assert message == expected_message, (
        f"the message must name the offending index key and sizes: expected "
        f"{expected_message!r}, got {message!r}"
    )

    assert ddb.get_item(TableName=table, Key={"pk": {"S": "valid"}, "sk": {"S": "1"}},
                        ConsistentRead=True).get("Item") is None, (
        "the well-formed sibling in a rejected batch must not be written"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "bad"}, "sk": {"S": "1"}},
                        ConsistentRead=True).get("Item") is None, (
        "the oversized-key item must not be written"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
