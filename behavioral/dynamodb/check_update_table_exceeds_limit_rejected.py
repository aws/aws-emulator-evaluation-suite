"""update-table-exceeds-limit-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable with two GSI creates in one call is rejected with LimitExceededException and its exact message,
    and leaves only gsi-pos, which a single-create UpdateTable added first; one GSI change per call is the limit
    clients rely on.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    # Positive control: a lone GSI create action in its own UpdateTable call
    # must be ACCEPTED (no exception) - this is what tells the negative below
    # apart from a target that rejects every GSI-via-UpdateTable call.
    ddb.update_table(
        TableName=table_name,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsiPos", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "gsi-pos",
                    "KeySchema": [{"AttributeName": "gsiPos", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                }
            },
        ],
    )

    err = _error(
        lambda: ddb.update_table(
            TableName=table_name,
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "gsiA", "AttributeType": "S"},
                {"AttributeName": "gsiB", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexUpdates=[
                {
                    "Create": {
                        "IndexName": "gsi-a",
                        "KeySchema": [{"AttributeName": "gsiA", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "KEYS_ONLY"},
                    }
                },
                {
                    "Create": {
                        "IndexName": "gsi-b",
                        "KeySchema": [{"AttributeName": "gsiB", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "KEYS_ONLY"},
                    }
                },
            ],
        )
    )
    assert err["Code"] == "LimitExceededException", f"expected LimitExceededException, got {err!r}"
    expected = "Subscriber limit exceeded: Only 1 online index can be created or deleted simultaneously per table"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # The rejected request applied neither create: the table is ACTIVE (or UPDATING while gsi-pos
    # backfills) with only gsi-pos.
    desc = ddb.describe_table(TableName=table_name)["Table"]
    assert desc["TableStatus"] in ("ACTIVE", "UPDATING"), (
        f"expected ACTIVE or UPDATING, got {desc['TableStatus']!r}"
    )
    gsi_names = {idx["IndexName"] for idx in desc.get("GlobalSecondaryIndexes", [])}
    assert gsi_names == {"gsi-pos"}, (
        f"expected only the positive-control gsi-pos to be present, found {gsi_names!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_table_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _safe_delete_table(ddb, table_name, timeout_s=600.0, interval_s=5.0):
    """Delete the table once no index is still building; DeleteTable refuses it before then."""
    from botocore.exceptions import ClientError

    try:
        deadline = time.monotonic() + timeout_s
        while True:
            desc = ddb.describe_table(TableName=table_name)["Table"]
            busy = [i for i in desc.get("GlobalSecondaryIndexes") or [] if i.get("IndexStatus") != "ACTIVE"]
            if desc["TableStatus"] == "ACTIVE" and not busy:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"table {table_name} indexes never settled for cleanup")
            time.sleep(interval_s)
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
