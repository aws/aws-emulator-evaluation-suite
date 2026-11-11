"""delete-table-with-active-gsi-reports-deleting."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-with-active-gsi-reports-deleting"
GROUP = "gsi"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTable on an ACTIVE table carrying an ACTIVE GSI answers TableStatus
    'DELETING' with no GlobalSecondaryIndexes member, and the table then settles to gone.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gsi_pk", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1",
                "KeySchema": [{"AttributeName": "gsi_pk", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))

    _wait_table_and_gsi_active(ddb, table, "gsi1")

    resp = ddb.delete_table(TableName=table)["TableDescription"]
    assert resp["TableStatus"] == "DELETING", (
        f"DeleteTable on an ACTIVE table with a GSI answered TableStatus {resp['TableStatus']!r}, "
        "expected 'DELETING'"
    )
    assert "GlobalSecondaryIndexes" not in resp, (
        f"DeleteTable response carried GlobalSecondaryIndexes {resp.get('GlobalSecondaryIndexes')!r}, "
        "expected the field to be omitted"
    )

    _wait_table_deleted(ddb, table)
    code, message = _error(lambda: ddb.describe_table(TableName=table))
    assert code == "ResourceNotFoundException", f"DescribeTable on the deleted table raised {code!r}"
    expected = f"Requested resource not found: Table: {table} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_table_and_gsi_active(ddb, table: str, index_name: str, *, timeout_s: float = 300.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        if last["TableStatus"] == "ACTIVE" and any(
            g["IndexName"] == index_name and g["IndexStatus"] == "ACTIVE"
            for g in last.get("GlobalSecondaryIndexes", [])
        ):
            return last
        time.sleep(2.0)
    raise AssertionError(f"table/index not both ACTIVE within {timeout_s}s. Last: {last!r}")


def _wait_table_deleted(ddb, table: str, *, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"table {table} still describable after {timeout_s}s")


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
