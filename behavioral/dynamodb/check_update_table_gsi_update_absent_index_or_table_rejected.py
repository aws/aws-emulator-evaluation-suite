"""update-table-gsi-update-absent-index-or-table-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-gsi-update-absent-index-or-table-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_HUGE_CAPACITY = 999999999
_ABSENT_INDEX = "absent-index-name"


def _teardown(undo, *not_found: str):
    """A cleanup running undo(); only the resource's own not-found codes mean it is gone."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _error(fn):
    """The (Code, Message) fn() raises. An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_active(ddb, table, deadline_s=240):
    end = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < end:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(3)
    raise AssertionError(f"{table} never became ACTIVE within {deadline_s}s: {desc!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable naming a GSI the table does not have is ResourceNotFoundException for that
    index even with an out-of-range capacity value, and naming a table that does not exist at
    all is ResourceNotFoundException for the table instead -- the table lookup runs first.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsiabs-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _wait_active(ddb, table)
    assert desc.get("GlobalSecondaryIndexes") is None, (
        f"the new table unexpectedly has GSIs {desc.get('GlobalSecondaryIndexes')!r}"
    )

    # Positive control: a well-formed UpdateTable call on this table is accepted and takes
    # effect, then rolled back so cleanup can delete the table normally.
    ddb.update_table(TableName=table, DeletionProtectionEnabled=True)
    desc = _wait_active(ddb, table)
    assert desc["DeletionProtectionEnabled"] is True, (
        f"the positive-control update left DeletionProtectionEnabled={desc['DeletionProtectionEnabled']!r}"
    )
    ddb.update_table(TableName=table, DeletionProtectionEnabled=False)
    desc = _wait_active(ddb, table)
    assert desc["DeletionProtectionEnabled"] is False, (
        f"turning deletion protection back off left DeletionProtectionEnabled={desc['DeletionProtectionEnabled']!r}"
    )

    # Break exactly one thing: Update a GSI the table never had, with an out-of-range RCU.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Update": {
            "IndexName": _ABSENT_INDEX,
            "ProvisionedThroughput": {"ReadCapacityUnits": _HUGE_CAPACITY, "WriteCapacityUnits": 5},
        }}],
    ))
    expected_rcu = (
        "ResourceNotFoundException",
        f"Requested resource not found: Index {_ABSENT_INDEX} for table {table}",
    )
    assert (code, msg) == expected_rcu, (
        f"Update of absent index {_ABSENT_INDEX!r} with a huge RCU gave {(code, msg)!r}, "
        f"expected {expected_rcu!r}"
    )

    # Same, with the huge value on WriteCapacityUnits instead.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Update": {
            "IndexName": _ABSENT_INDEX,
            "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": _HUGE_CAPACITY},
        }}],
    ))
    expected_wcu = (
        "ResourceNotFoundException",
        f"Requested resource not found: Index {_ABSENT_INDEX} for table {table}",
    )
    assert (code, msg) == expected_wcu, (
        f"Update of absent index {_ABSENT_INDEX!r} with a huge WCU gave {(code, msg)!r}, "
        f"expected {expected_wcu!r}"
    )

    # Break the other thing: the TABLE itself does not exist; the table lookup wins over the
    # index lookup and the capacity value, even though the same absent index name is used.
    absent_table = ctx.unique_name("sim2real-behav-ddb-gsiabs-notable-")
    code, msg = _error(lambda: ddb.update_table(
        TableName=absent_table,
        GlobalSecondaryIndexUpdates=[{"Update": {
            "IndexName": _ABSENT_INDEX,
            "ProvisionedThroughput": {"ReadCapacityUnits": _HUGE_CAPACITY, "WriteCapacityUnits": 5},
        }}],
    ))
    expected_table = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {absent_table} not found",
    )
    assert (code, msg) == expected_table, (
        f"Update against a nonexistent table gave {(code, msg)!r}, expected {expected_table!r}"
    )

    # None of the three refusals changed the real table.
    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc.get("GlobalSecondaryIndexes") is None, (
        f"after the refused Updates the table has GSIs {desc.get('GlobalSecondaryIndexes')!r}"
    )
    assert desc["DeletionProtectionEnabled"] is False, (
        f"after the refused Updates DeletionProtectionEnabled drifted to {desc['DeletionProtectionEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
