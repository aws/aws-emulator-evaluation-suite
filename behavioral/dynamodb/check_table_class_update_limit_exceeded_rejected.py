"""table-class-update-limit-exceeded-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "table-class-update-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A table's class moves STANDARD_INFREQUENT_ACCESS then back to STANDARD; a third change
    within 30 days is rejected with LimitExceededException and its exact message, and the table's
    class stays at the last accepted value.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _wait_table_active(ddb, table_name)

    ddb.update_table(TableName=table_name, TableClass="STANDARD_INFREQUENT_ACCESS")
    desc = _wait_table_active(ddb, table_name)
    assert desc["TableClassSummary"]["TableClass"] == "STANDARD_INFREQUENT_ACCESS", (
        f"expected STANDARD_INFREQUENT_ACCESS after the first change, got {desc.get('TableClassSummary')!r}"
    )

    ddb.update_table(TableName=table_name, TableClass="STANDARD")
    desc = _wait_table_active(ddb, table_name)
    assert desc["TableClassSummary"]["TableClass"] == "STANDARD", (
        f"expected STANDARD after the second change, got {desc.get('TableClassSummary')!r}"
    )

    err = _error(lambda: ddb.update_table(TableName=table_name, TableClass="STANDARD_INFREQUENT_ACCESS"))
    assert err["Code"] == "LimitExceededException", f"expected LimitExceededException, got {err!r}"
    expected_message = "Subscriber limit exceeded: Updates to TableClass are limited to 2 times in 30 day(s)."
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err['Message']!r}"
    )

    desc = ddb.describe_table(TableName=table_name)["Table"]
    assert desc["TableClassSummary"]["TableClass"] == "STANDARD", (
        f"the rejected third change must leave the table at STANDARD, got {desc.get('TableClassSummary')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS rejects is the strongest signal available."""
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


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
