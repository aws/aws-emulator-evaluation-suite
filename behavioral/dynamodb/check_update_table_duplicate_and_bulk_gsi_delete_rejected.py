"""update-table-duplicate-and-bulk-gsi-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-duplicate-and-bulk-gsi-delete-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

#: Six indexes the table declares at create time, each on its own hash-key attribute.
_INDEX_NAMES = ["idx-a", "idx-b", "idx-c", "idx-d", "idx-e", "idx-f"]
_HASH_ATTRS = ["ga", "gb", "gc", "gd", "ge", "gf"]


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


def _wait_settled(ddb, table, deadline_s=240):
    """Poll DescribeTable until ACTIVE with every index ACTIVE."""
    end = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < end:
        desc = ddb.describe_table(TableName=table)["Table"]
        busy = [i for i in desc.get("GlobalSecondaryIndexes") or []
                if i.get("IndexStatus") != "ACTIVE"]
        if desc["TableStatus"] == "ACTIVE" and not busy:
            return desc
        time.sleep(3)
    raise AssertionError(f"{table} never settled to ACTIVE within {deadline_s}s: {desc!r}")


def _index_names(desc) -> list:
    return sorted(i["IndexName"] for i in desc.get("GlobalSecondaryIndexes") or [])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable naming one index in two Delete actions is refused for carrying more than one
    update for that index, and deleting six different indexes in one call hits the one-online-
    index-change limit instead; neither rejected call changes the table's indexes.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsidup-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}] + [
            {"AttributeName": attr, "AttributeType": "S"} for attr in _HASH_ATTRS
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[
            {"IndexName": name,
             "KeySchema": [{"AttributeName": attr, "KeyType": "HASH"}],
             "Projection": {"ProjectionType": "KEYS_ONLY"}}
            for name, attr in zip(_INDEX_NAMES, _HASH_ATTRS)
        ],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _wait_settled(ddb, table)
    assert _index_names(desc) == sorted(_INDEX_NAMES), (
        f"the new table lists GSIs {_index_names(desc)!r}, expected all six"
    )

    # Break exactly one thing: name the SAME existing index in two Delete actions.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[
            {"Delete": {"IndexName": "idx-a"}},
            {"Delete": {"IndexName": "idx-a"}},
        ]))
    expected_dup = (
        "ValidationException",
        "One or more parameter values were invalid: Only one global secondary index update "
        "per index is allowed simultaneously. Index: idx-a",
    )
    assert (code, msg) == expected_dup, (
        f"two Deletes of the same index idx-a gave {(code, msg)!r}, expected {expected_dup!r}"
    )
    desc = _wait_settled(ddb, table)
    assert _index_names(desc) == sorted(_INDEX_NAMES), (
        f"after the refused duplicate-delete the table lists GSIs {_index_names(desc)!r}"
    )

    # Break the other thing: six Deletes, each naming a different existing index.
    code, msg = _error(lambda: ddb.update_table(
        TableName=table,
        GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": name}} for name in _INDEX_NAMES]))
    expected_bulk = (
        "LimitExceededException",
        "Subscriber limit exceeded: Only 1 online index can be created or deleted "
        "simultaneously per table",
    )
    assert (code, msg) == expected_bulk, (
        f"six Deletes of six different indexes gave {(code, msg)!r}, expected {expected_bulk!r}"
    )
    desc = _wait_settled(ddb, table)
    assert _index_names(desc) == sorted(_INDEX_NAMES), (
        f"after the refused bulk-delete the table lists GSIs {_index_names(desc)!r}"
    )

    # Positive control: deleting ONE of the six in its own call is accepted and takes effect.
    ddb.update_table(
        TableName=table, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": "idx-a"}}])
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 600.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if "idx-a" not in _index_names(desc):
            break
        time.sleep(3)
    assert _index_names(desc) == sorted(n for n in _INDEX_NAMES if n != "idx-a"), (
        f"deleting idx-a alone left GSIs {_index_names(desc)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
