"""update-table-gsi-add-duplicate-attribute-name-in-attribute-definitions-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-add-duplicate-attribute-name-in-attribute-definitions-rejected"
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


def _safe_delete_table(ddb, name):
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding a GSI with the same AttributeDefinitions name declared twice at different types is
    rejected and leaves the table with no new index and its one attribute unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsidup-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    code, message = _error(
        lambda: ddb.update_table(
            TableName=table,
            AttributeDefinitions=[
                {"AttributeName": "g1", "AttributeType": "S"},
                {"AttributeName": "g1", "AttributeType": "N"},
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
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_msg = "Attribute Name is duplicated: g1"
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    after_reject = ddb.describe_table(TableName=table)["Table"]
    assert "GlobalSecondaryIndexes" not in after_reject, (
        f"a rejected GSI add must create no index, got {after_reject.get('GlobalSecondaryIndexes')!r}"
    )
    after_reject_attrs = {
        a["AttributeName"]: a["AttributeType"] for a in after_reject["AttributeDefinitions"]
    }
    assert after_reject_attrs == {"pk": "S"}, (
        f"a rejected GSI add must leave AttributeDefinitions alone, got {after_reject_attrs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
