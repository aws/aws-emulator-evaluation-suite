"""create-table-exceeds-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-table-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable adding a 21st global secondary index to a table at the default quota of 20 fails with
    LimitExceededException and AWS's exact message, and the index is not added."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")

    num_initial_gsis = 20  # default per-table quota is 20 global secondary indexes
    attribute_definitions = [{"AttributeName": "pk", "AttributeType": "S"}]
    gsis = []
    for i in range(num_initial_gsis):
        attr = f"gsi{i}pk"
        attribute_definitions.append({"AttributeName": attr, "AttributeType": "S"})
        gsis.append(
            {
                "IndexName": f"gsi{i}",
                "KeySchema": [{"AttributeName": attr, "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            }
        )

    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=attribute_definitions,
        GlobalSecondaryIndexes=gsis,
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_all_gsi_active(ddb, table_name)

    # The table is already at the 20-GSI quota; adding a 21st must be
    # rejected wholesale.
    code, message = _error(
        lambda: ddb.update_table(
            TableName=table_name,
            AttributeDefinitions=[{"AttributeName": "gsi20pk", "AttributeType": "S"}],
            GlobalSecondaryIndexUpdates=[
                {
                    "Create": {
                        "IndexName": "gsi20",
                        "KeySchema": [{"AttributeName": "gsi20pk", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "KEYS_ONLY"},
                    }
                }
            ],
        )
    )
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code!r}"
    expected_msg = (
        "Subscriber limit exceeded: Number of global secondary indexes exceeds per-table limit of 20"
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # The over-limit 21st index must not have actually been created.
    desc = ddb.describe_table(TableName=table_name)["Table"]
    gsi_names = {g["IndexName"] for g in desc.get("GlobalSecondaryIndexes", [])}
    assert "gsi20" not in gsi_names, (
        f"expected the rejected 21st GSI to not exist, found indexes {gsi_names!r}"
    )


def _error(fn):
    """Call fn() and return the (Code, Message) of the ClientError it raises; an accepted call
    is itself a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _wait_all_gsi_active(ddb, table_name, timeout_s=600.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        gsis = desc.get("GlobalSecondaryIndexes", [])
        if desc["TableStatus"] == "ACTIVE" and all(
            g["IndexStatus"] == "ACTIVE" for g in gsis
        ):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} and its GSIs never became ACTIVE")


def _safe_delete_table(ddb, table_name):
    from botocore.exceptions import ClientError

    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
