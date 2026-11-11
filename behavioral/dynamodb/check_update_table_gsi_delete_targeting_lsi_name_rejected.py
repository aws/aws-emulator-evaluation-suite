"""update-table-gsi-delete-targeting-lsi-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-delete-targeting-lsi-name-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_table_settled(ddb, name, timeout_s=1500.0, interval_s=5.0):
    """Poll DescribeTable until the table and every index are ACTIVE."""
    deadline = time.monotonic() + timeout_s
    table = None
    while time.monotonic() < deadline:
        table = ddb.describe_table(TableName=name)["Table"]
        busy = [
            i for i in table.get("GlobalSecondaryIndexes") or [] if i.get("IndexStatus") != "ACTIVE"
        ]
        if table["TableStatus"] == "ACTIVE" and not busy:
            return table
        time.sleep(interval_s)
    raise AssertionError(f"{name} never settled to ACTIVE within {timeout_s}s; last={table!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable's GlobalSecondaryIndexUpdates Delete rejects an IndexName that names a
    local secondary index instead of a global one, leaving every index untouched, and a
    Delete naming the real GSI then succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsidel-")

    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "shared_attr", "AttributeType": "S"},
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": "lsi-main",
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "shared_attr", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi-main",
                "KeySchema": [{"AttributeName": "shared_attr", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_settled(ddb, table)

    code, message = _error(
        lambda: ddb.update_table(
            TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "lsi-main"}}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = "Cannot delete an index that is not a GlobalSecondaryIndex: lsi-main"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected call must not have touched either index.
    after_reject = ddb.describe_table(TableName=table)["Table"]
    gsi_names = [g["IndexName"] for g in after_reject.get("GlobalSecondaryIndexes") or []]
    lsi_names = [i["IndexName"] for i in after_reject.get("LocalSecondaryIndexes") or []]
    assert gsi_names == ["gsi-main"], f"rejected delete must leave the GSI alone, got {gsi_names!r}"
    assert lsi_names == ["lsi-main"], f"rejected delete must leave the LSI alone, got {lsi_names!r}"

    # Positive control: naming the real GSI succeeds.
    ddb.update_table(
        TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "gsi-main"}}]
    )
    settled = _wait_table_settled(ddb, table)
    assert settled.get("GlobalSecondaryIndexes") in (None, []), (
        f"expected gsi-main gone after the real delete, got {settled.get('GlobalSecondaryIndexes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
