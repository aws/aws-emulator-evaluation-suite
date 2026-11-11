"""update-table-gsi-attribute-definitions-track-live-keys."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-attribute-definitions-track-live-keys"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_WAIT_S = 1500.0


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_table_settled(ddb, name, timeout_s=_WAIT_S, interval_s=5.0):
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


def _delete_table(ddb, name):
    def run_undo() -> None:
        try:
            ddb.delete_table(TableName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable's GlobalSecondaryIndexUpdates leaves AttributeDefinitions as exactly the
    attributes a live key still uses after a GSI create and delete, and rejects a GSI keyed on
    an undeclared attribute and a throughput update that changes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")

    # --- Provisioned-throughput no-op rejection, with a positive control. ---
    prov_table = ctx.unique_name("sim2real-behav-ddb-prov-")
    ddb.create_table(
        TableName=prov_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    ctx.on_cleanup(_delete_table(ddb, prov_table))
    _wait_table_settled(ddb, prov_table)

    # Positive control: changing the throughput to a genuinely different value succeeds.
    ddb.update_table(
        TableName=prov_table,
        ProvisionedThroughput={"ReadCapacityUnits": 7, "WriteCapacityUnits": 7},
    )
    settled = _wait_table_settled(ddb, prov_table)
    pt = settled["ProvisionedThroughput"]
    assert pt["ReadCapacityUnits"] == 7 and pt["WriteCapacityUnits"] == 7, (
        f"expected 7/7 after the throughput update, got {pt!r}"
    )

    code, message = _error(
        lambda: ddb.update_table(
            TableName=prov_table,
            ProvisionedThroughput={"ReadCapacityUnits": 7, "WriteCapacityUnits": 7},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_noop_msg = (
        "The provisioned throughput for the table will not change. The requested value equals "
        "the current value. Current ReadCapacityUnits provisioned for the table: 7. Requested "
        "ReadCapacityUnits: 7. Current WriteCapacityUnits provisioned for the table: 7. Requested "
        "WriteCapacityUnits: 7. Refer to the Amazon DynamoDB Developer Guide for current limits "
        "and how to request higher limits."
    )
    assert message == expected_noop_msg, f"expected message {expected_noop_msg!r}, got {message!r}"

    # --- GSI create/delete tracks AttributeDefinitions; undeclared-key rejection. ---
    table = ctx.unique_name("sim2real-behav-ddb-gsi-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_delete_table(ddb, table))
    _wait_table_settled(ddb, table)

    # Create a GSI while also declaring an AttributeDefinition no key (base or index) uses.
    ddb.update_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "g1", "AttributeType": "S"},
            {"AttributeName": "unused", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "gsi-main",
                    "KeySchema": [{"AttributeName": "g1", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    created = _wait_table_settled(ddb, table)
    created_attrs = {
        a["AttributeName"]: a["AttributeType"] for a in created["AttributeDefinitions"]
    }
    assert created_attrs == {"pk": "S", "g1": "S"}, (
        f"expected AttributeDefinitions to hold only the live keys {{'pk': 'S', 'g1': 'S'}}, "
        f"got {created_attrs!r}"
    )

    # Rejection: a second GSI keyed on an attribute never declared in AttributeDefinitions.
    code, message = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            GlobalSecondaryIndexUpdates=[
                {
                    "Create": {
                        "IndexName": "gsi-undeclared",
                        "KeySchema": [{"AttributeName": "undeclared_attr", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_undeclared_msg = (
        "One or more parameter values were invalid: Some index key attributes are not defined "
        "in AttributeDefinitions. Keys: [undeclared_attr], AttributeDefinitions: [pk]"
    )
    assert message == expected_undeclared_msg, (
        f"expected message {expected_undeclared_msg!r}, got {message!r}"
    )

    # The rejected create must not have touched the table: same index, same attributes.
    after_reject = ddb.describe_table(TableName=table)["Table"]
    gsi_names = [g["IndexName"] for g in after_reject.get("GlobalSecondaryIndexes") or []]
    assert gsi_names == ["gsi-main"], f"rejected create must leave the index set alone, got {gsi_names!r}"
    after_reject_attrs = {
        a["AttributeName"]: a["AttributeType"] for a in after_reject["AttributeDefinitions"]
    }
    assert after_reject_attrs == {"pk": "S", "g1": "S"}, (
        f"rejected create must leave AttributeDefinitions alone, got {after_reject_attrs!r}"
    )

    # Delete the GSI; the attribute it alone used drops out of AttributeDefinitions too.
    ddb.update_table(
        TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "gsi-main"}}]
    )
    deleted = _wait_table_settled(ddb, table)
    assert deleted.get("GlobalSecondaryIndexes") in (None, []), (
        f"expected no indexes after delete, got {deleted.get('GlobalSecondaryIndexes')!r}"
    )
    deleted_attrs = {
        a["AttributeName"]: a["AttributeType"] for a in deleted["AttributeDefinitions"]
    }
    assert deleted_attrs == {"pk": "S"}, (
        f"expected AttributeDefinitions to shrink back to the base key {{'pk': 'S'}}, "
        f"got {deleted_attrs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
