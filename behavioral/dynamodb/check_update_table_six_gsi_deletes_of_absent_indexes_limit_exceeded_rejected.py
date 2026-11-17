"""update-table-six-gsi-deletes-of-absent-indexes-limit-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-six-gsi-deletes-of-absent-indexes-limit-exceeded-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_ABSENT_NAMES = [f"absent-idx-{i}" for i in range(6)]


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
    """UpdateTable deleting six GSIs the table never had answers the one-online-index-change
    LimitExceededException, while a single Delete of one absent GSI answers that index's own
    ResourceNotFoundException: the count is checked before the index lookup.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsidelabs-")
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

    # Break exactly one thing: six Deletes, each naming a GSI the table never had.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": name}} for name in _ABSENT_NAMES]))
    expected_limit = (
        "LimitExceededException",
        "Subscriber limit exceeded: Only 1 online index can be created or deleted "
        "simultaneously per table",
    )
    assert (code, msg) == expected_limit, (
        f"six Deletes of six absent indexes gave {(code, msg)!r}, expected {expected_limit!r}"
    )
    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc.get("GlobalSecondaryIndexes") is None, (
        f"after the refused bulk delete the table has GSIs {desc.get('GlobalSecondaryIndexes')!r}"
    )

    # Contrast: a lone Delete of one of the same absent names falls through the count check
    # and hits that index's own not-found error instead.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": _ABSENT_NAMES[0]}}]))
    expected_not_found = (
        "ResourceNotFoundException",
        f"Requested resource not found: Index {_ABSENT_NAMES[0]} for table {table}",
    )
    assert (code, msg) == expected_not_found, (
        f"a single Delete of the absent index {_ABSENT_NAMES[0]!r} gave {(code, msg)!r}, "
        f"expected {expected_not_found!r}"
    )

    desc = ddb.describe_table(TableName=table)["Table"]
    assert desc.get("GlobalSecondaryIndexes") is None, (
        f"after both refusals the table has GSIs {desc.get('GlobalSecondaryIndexes')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
