"""partition-index-backfill-rejects-a-type-violating-partition-value."""
# CreatePartition does not type-check a partition value against its key's declared type: a table
# whose only partition key is `pk int` accepts Values=["not-an-int"], and GetPartition reads it
# back. Registering a partition index over a table that already holds such a partition drives the
# index to IndexStatus=FAILED and populates PartitionIndexDescriptor.BackfillErrors with
# INVALID_PARTITION_TYPE_DATA_ERROR naming the offending partition
# (https://docs.aws.amazon.com/glue/latest/webapi/API_BackfillError.html). A partition index is
# created with the partition-key name in `Keys`, and GetPartitionIndexes echoes the key with its
# declared type. Both index builds reach a terminal status within 480 s.
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partition-index-backfill-rejects-a-type-violating-partition-value"
GROUP = "partition"
SERVICES = ["glue"]

_GOOD_VALUE = "7"
_BAD_VALUE = "not-an-int"


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The catalog stores an untyped partition value but its index backfill refuses it."""
    glue = ctx.client("glue")

    database = ctx.unique_name("sim2real_behav_pidx_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    # Two tables identical in every respect except the ONE partition value they hold. That is
    # the twin control group in the same instant: `clean` proves this account, this
    # database and this index shape can reach ACTIVE, so `dirty` reaching FAILED is a verdict
    # on the data and not on the wiring.
    clean = _create_partitioned_table(ctx, glue, database, "clean", _GOOD_VALUE)
    dirty = _create_partitioned_table(ctx, glue, database, "dirty", _BAD_VALUE)

    # Leg 1 — the store side of the inversion. CreatePartition accepted a value that is not
    # an int for a key declared `int`, and an independent read through a different operation
    # confirms the catalog is really holding it. An emulator that type-checks here diverges
    # from Glue, and the message says so.
    stored = glue.get_partition(
        DatabaseName=database, TableName=dirty, PartitionValues=[_BAD_VALUE]
    )["Partition"]
    assert stored["Values"] == [_BAD_VALUE], (
        f"GetPartition({database}.{dirty}) returned Values={stored.get('Values')!r}, "
        f"expected [{_BAD_VALUE!r}]: Glue stores partition values verbatim and does not "
        f"validate them against the partition key's declared int type at CreatePartition"
    )
    declared = glue.get_table(DatabaseName=database, Name=dirty)["Table"]["PartitionKeys"]
    assert [(k["Name"], k["Type"]) for k in declared] == [("pk", "int")], (
        f"{database}.{dirty} declares PartitionKeys={declared!r}; the check needs exactly "
        f"one key `pk int` for the type violation to be the only difference from the twin"
    )

    # Leg 2 — the enforce side. Register the same index shape on both tables at the same
    # moment, then wait for both to leave CREATING.
    index_name = "pk-index"
    for table in (clean, dirty):
        glue.create_partition_index(
            DatabaseName=database,
            TableName=table,
            PartitionIndex={"IndexName": index_name, "Keys": ["pk"]},
        )
        ctx.on_cleanup(lambda t=table: _retry_delete(
            lambda: glue.delete_partition_index(
                DatabaseName=database, TableName=t, IndexName=index_name),
            f"partition index {database}.{t}/{index_name}"))

    def _descriptors() -> dict[str, dict]:
        out = {}
        for table in (clean, dirty):
            found = [
                d for d in glue.get_partition_indexes(
                    DatabaseName=database, TableName=table
                )["PartitionIndexDescriptorList"]
                if d["IndexName"] == index_name
            ]
            assert len(found) == 1, (
                f"GetPartitionIndexes({database}.{table}) reported {len(found)} indexes "
                f"named {index_name!r}, expected exactly 1"
            )
            out[table] = found[0]
        return out

    settled = _poll_until(
        _descriptors,
        lambda d: all(v["IndexStatus"] in ("ACTIVE", "FAILED") for v in d.values()),
        timeout_s=480.0,
        interval_s=10.0,
        reason=("a partition index backfills existing partitions asynchronously; both "
                "indexes must leave CREATING before their verdicts can be compared"),
    )

    assert settled[clean]["IndexStatus"] == "ACTIVE", (
        f"the control index on {database}.{clean} — same shape, same key, one partition "
        f"whose value {_GOOD_VALUE!r} IS a valid int — settled at "
        f"{settled[clean]['IndexStatus']!r} with BackfillErrors="
        f"{settled[clean].get('BackfillErrors')!r}; without a passing control the FAILED "
        f"verdict below would be indistinguishable from every index failing"
    )
    assert settled[dirty]["IndexStatus"] == "FAILED", (
        f"the index on {database}.{dirty}, whose single partition value {_BAD_VALUE!r} is "
        f"not an int, settled at {settled[dirty]['IndexStatus']!r}; the identical index on "
        f"{clean} is ACTIVE, so the backfill is not enforcing the partition key's declared "
        f"type against the stored value"
    )

    errors = settled[dirty]["BackfillErrors"]
    codes = [e["Code"] for e in errors]
    assert codes == ["INVALID_PARTITION_TYPE_DATA_ERROR"], (
        f"BackfillErrors for {database}.{dirty} carried codes {codes!r}, expected exactly "
        f"['INVALID_PARTITION_TYPE_DATA_ERROR'] — the code Glue documents for 'the partition "
        f"value doesn't match the data type for that partition column'. Full errors: "
        f"{errors!r}"
    )
    offending = [tuple(p["Values"]) for p in errors[0]["Partitions"]]
    assert offending == [(_BAD_VALUE,)], (
        f"BackfillErrors[0].Partitions named {offending!r}; the table holds exactly one "
        f"partition, {[_BAD_VALUE]!r}, so that is the only partition at fault and the error "
        f"must identify it"
    )

    # Leg 3 — the failed index is still a real, addressable object, and the control index is
    # still ACTIVE afterwards: reading the failure did not advance or clear either state.
    reread = _descriptors()
    assert reread[dirty]["IndexStatus"] == "FAILED", (
        f"re-reading GetPartitionIndexes changed {dirty}'s IndexStatus from FAILED to "
        f"{reread[dirty]['IndexStatus']!r}; a read must not advance index state"
    )
    assert reread[clean]["IndexStatus"] == "ACTIVE", (
        f"re-reading GetPartitionIndexes changed {clean}'s IndexStatus from ACTIVE to "
        f"{reread[clean]['IndexStatus']!r}; a read must not advance index state"
    )


def _create_partitioned_table(ctx, glue, database: str, label: str, value: str) -> str:
    """A table with one `pk int` partition key holding exactly one partition, value `value`."""
    name = ctx.unique_name(f"sim2real_behav_{label}_").replace("-", "_")
    glue.create_table(
        DatabaseName=database,
        TableInput={
            "Name": name,
            "StorageDescriptor": {
                "Columns": [{"Name": "payload", "Type": "string"}],
                "Location": f"s3://example-bucket/{name}/",
            },
            "PartitionKeys": [{"Name": "pk", "Type": "int"}],
            "Parameters": {"sim2real": CHECK},
        },
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=name),
        f"glue table {database}.{name}"))
    glue.create_partition(
        DatabaseName=database,
        TableName=name,
        PartitionInput={
            "Values": [value],
            "StorageDescriptor": {
                "Columns": [{"Name": "payload", "Type": "string"}],
                "Location": f"s3://example-bucket/{name}/pk={value}/",
            },
        },
    )
    return name


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s ({reason}); "
                f"last value={last!r}"
            )
        time.sleep(interval_s)


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "ResourceNotFoundException")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
