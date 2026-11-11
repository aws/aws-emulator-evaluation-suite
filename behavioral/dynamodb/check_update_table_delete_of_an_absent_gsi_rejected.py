"""update-table-delete-of-an-absent-gsi-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-delete-of-an-absent-gsi-rejected"
GROUP = "tables"
SERVICES = ["dynamodb"]

_KEPT = "by-g"
_ABSENT = "by-nothing"


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _indexes(desc):
    return sorted(g["IndexName"] for g in desc.get("GlobalSecondaryIndexes", []))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable deleting a GSI the table does not have is ResourceNotFoundException and leaves the
    existing GSI in place; deleting the existing GSI then removes it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsidel-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "g", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{
            "IndexName": _KEPT,
            "KeySchema": [{"AttributeName": "g", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _wait_active(ddb, ctx, table)
    assert _indexes(desc) == [_KEPT], f"the new table lists GSIs {_indexes(desc)!r}"

    code, msg = _error(lambda: ddb.update_table(
        TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": _ABSENT}}]))
    want = ("ResourceNotFoundException", f"Requested resource not found: Index {_ABSENT} for table {table}")
    assert (code, msg) == want, f"deleting the absent GSI {_ABSENT!r} gave {code!r}: {msg!r}"
    desc = _wait_active(ddb, ctx, table)
    assert _indexes(desc) == [_KEPT], f"after the refused delete the table lists GSIs {_indexes(desc)!r}"

    ddb.update_table(TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": _KEPT}}])
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 600.0) - 30.0)
    while True:
        desc = ddb.describe_table(TableName=table)["Table"]
        if not _indexes(desc) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert _indexes(desc) == [], f"deleting the existing GSI left {_indexes(desc)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
