"""create-table-partition-indexes-then-delete-missing-table-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-table-partition-indexes-then-delete-missing-table-rejected"
GROUP = "partition"
SERVICES = ["glue"]


def _error_code(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry that raises on timeout, never returns a stale value."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s ({reason}); last value={value!r}"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable's PartitionIndexes builds a real index that settles ACTIVE with its declared
    keys; DeletePartitionIndex naming a table absent from the database is refused by the table
    lookup, leaving the index untouched, while the identical call against the real table deletes it.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_behav_ptidx_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real_behav_tbl_")
    index_name = ctx.unique_name("sim2real-behav-idx-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "payload", "Type": "string"}],
                "Location": f"s3://example-bucket/{tbl_name}/",
            },
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
        PartitionIndexes=[{"IndexName": index_name, "Keys": ["dt"]}],
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    def _descriptor():
        found = [
            d for d in glue.get_partition_indexes(
                DatabaseName=db_name, TableName=tbl_name
            )["PartitionIndexDescriptorList"]
            if d["IndexName"] == index_name
        ]
        assert len(found) == 1, (
            f"GetPartitionIndexes reported {len(found)} indexes named {index_name!r}, expected 1"
        )
        return found[0]

    settled = _poll_until(
        _descriptor,
        lambda d: d["IndexStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=240.0,
        interval_s=5.0,
        reason="an index named in CreateTable's PartitionIndexes builds asynchronously",
    )
    assert settled["IndexStatus"] == "ACTIVE", (
        f"the index created via CreateTable's PartitionIndexes settled at "
        f"{settled['IndexStatus']!r}, expected ACTIVE"
    )
    assert settled["Keys"] == [{"Name": "dt", "Type": "string"}], (
        f"GetPartitionIndexes reported Keys={settled['Keys']!r} for the index built from "
        f"CreateTable's PartitionIndexes, expected the declared partition key dt typed string"
    )

    missing_tbl = ctx.unique_name("sim2real_behav_missing_tbl_")
    code, message = _error_code(
        lambda: glue.delete_partition_index(
            DatabaseName=db_name, TableName=missing_tbl, IndexName=index_name
        )
    )
    assert (code, message) == ("EntityNotFoundException", f"Table {missing_tbl} not found."), (
        f"DeletePartitionIndex naming a table absent from {db_name} returned {(code, message)!r}"
    )

    # Effect absent: the attempted delete against the wrong table left the real index
    # untouched, still ACTIVE with its original keys.
    unaffected = _descriptor()
    assert unaffected["IndexStatus"] == "ACTIVE" and unaffected["Keys"] == [
        {"Name": "dt", "Type": "string"}
    ], (
        f"the index on {tbl_name} changed after a DeletePartitionIndex call naming a "
        f"different table: {unaffected!r}"
    )

    # Positive control: the identical call, pointed at the table that actually holds the
    # index, succeeds — the table name was the one broken thing.
    glue.delete_partition_index(DatabaseName=db_name, TableName=tbl_name, IndexName=index_name)

    def _index_names():
        return [
            d["IndexName"]
            for d in glue.get_partition_indexes(
                DatabaseName=db_name, TableName=tbl_name
            )["PartitionIndexDescriptorList"]
        ]

    emptied = _poll_until(
        _index_names,
        lambda names: names == [],
        timeout_s=120.0,
        interval_s=5.0,
        reason="a deleted partition index must leave GetPartitionIndexes empty",
    )
    assert emptied == [], (
        f"GetPartitionIndexes still listed {emptied!r} after DeletePartitionIndex succeeded"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
