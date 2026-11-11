"""partition-index-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "partition-index-lifecycle"
GROUP = 'partition'
SERVICES = ['glue']

def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPartitionIndexes returns the created index with its exact keys once ACTIVE.

    The same call for a missing table is refused with EntityNotFoundException and its exact message.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    glue.create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInput={
            "Values": ["2024-05-01"],
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/dt=2024-05-01/",
            },
        },
    )

    index_name = ctx.unique_name("sim2real-behav-idx-")
    glue.create_partition_index(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionIndex={"IndexName": index_name, "Keys": ["dt"]},
    )

    def get_status():
        descriptors = glue.get_partition_indexes(
            DatabaseName=db_name, TableName=tbl_name
        )["PartitionIndexDescriptorList"]
        match = next((d for d in descriptors if d["IndexName"] == index_name), None)
        return match["IndexStatus"] if match else None

    # The index build is asynchronous on real Glue; wait for it to settle. One body for
    # both transports — an emulator that reports the index immediately just satisfies
    # the poll predicate on its first call.
    final_status = _poll(get_status, lambda s: s in ("ACTIVE", "FAILED"), timeout_s=240, interval_s=5)
    assert final_status == "ACTIVE", f"partition index build did not become ACTIVE: {final_status}"

    # The ACTIVE descriptor echoes the index's key with the partition column's declared type.
    want_descriptors = [
        {
            "IndexName": index_name,
            "Keys": [{"Name": "dt", "Type": "string"}],
            "IndexStatus": "ACTIVE",
        }
    ]
    descriptors = glue.get_partition_indexes(
        DatabaseName=db_name, TableName=tbl_name
    )["PartitionIndexDescriptorList"]
    assert descriptors == want_descriptors, (
        f"GetPartitionIndexes returned {descriptors!r}, expected {want_descriptors!r}"
    )

    missing_tbl = ctx.unique_name("sim2real-behav-tbl-missing-")
    code, message = _error_code(
        lambda: glue.get_partition_indexes(DatabaseName=db_name, TableName=missing_tbl)
    )
    assert (code, message) == ("EntityNotFoundException", f"Table {missing_tbl} not found."), (
        f"GetPartitionIndexes on a missing table returned {(code, message)!r}"
    )

    glue.delete_partition_index(DatabaseName=db_name, TableName=tbl_name, IndexName=index_name)

    def index_names():
        return [
            d["IndexName"]
            for d in glue.get_partition_indexes(
                DatabaseName=db_name, TableName=tbl_name
            )["PartitionIndexDescriptorList"]
        ]

    gone = _poll(index_names, lambda names: index_name not in names, timeout_s=120, interval_s=5)
    assert index_name not in gone, (
        f"deleted partition index must disappear from GetPartitionIndexes: {gone}"
    )

    # The dead index id must also be unusable: deleting it again is a not-found, not a success.
    expected_message = f"Index with the given indexName : {index_name} does not exist."
    code, message = _error_code(
        lambda: glue.delete_partition_index(DatabaseName=db_name, TableName=tbl_name, IndexName=index_name)
    )
    assert code == "EntityNotFoundException", (
        f"deleting an already-deleted partition index must be EntityNotFoundException, got {code}"
    )
    assert message == expected_message, (
        f"expected DeletePartitionIndex message {expected_message!r}, got {message!r}"
    )


# ===== helpers =====
def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
