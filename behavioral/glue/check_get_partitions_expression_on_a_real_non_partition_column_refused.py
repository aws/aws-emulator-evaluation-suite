"""get-partitions-expression-on-a-real-non-partition-column-refused."""
# GetPartitions' Expression may only reference partition keys, so a predicate on `payload` -- a
# column in the table's StorageDescriptor.Columns that is not a partition key -- is refused with
# InvalidInputException (https://docs.aws.amazon.com/glue/latest/webapi/API_GetPartitions.html).
# Promoting the same column to a partition key on an otherwise identical twin table makes the
# identical predicate legal, so the refusal is about partition-key-ness, not the column name or
# the literal. `dt = '2024-01-01'` on a string partition key matches the one partition created
# here exactly. A non-partition column can never become a partition column of that table, so
# there is no restore step; the positive control and the re-proof after the refusal are present.
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-partitions-expression-on-a-real-non-partition-column-refused"
GROUP = "partition"
SERVICES = ["glue"]

_LEGAL = "dt = '2024-01-01'"
_ILLEGAL = "payload = 'hello'"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A GetPartitions predicate on a real non-partition column is refused; on a partition key it is not."""
    glue = ctx.client("glue")

    database = ctx.unique_name("sim2real_behav_gpexpr_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    # `subject`: payload is a data column. `twin`: payload is a partition key. Nothing else
    # differs, so the twin isolates partition-key-ness as the only variable.
    subject = _create_table(ctx, glue, database, "subject",
                            columns=[{"Name": "payload", "Type": "string"}],
                            partition_keys=[{"Name": "dt", "Type": "string"}],
                            partition_values=["2024-01-01"])
    twin = _create_table(ctx, glue, database, "twin",
                         columns=[{"Name": "other", "Type": "string"}],
                         partition_keys=[{"Name": "dt", "Type": "string"},
                                         {"Name": "payload", "Type": "string"}],
                         partition_values=["2024-01-01", "hello"])

    # The subject really does have `payload` as a data column and NOT as a partition key.
    # Without this the refusal below could just be "unknown column", which the sibling check
    # already grades.
    table = glue.get_table(DatabaseName=database, Name=subject)["Table"]
    data_columns = [c["Name"] for c in table["StorageDescriptor"]["Columns"]]
    partition_columns = [k["Name"] for k in table["PartitionKeys"]]
    assert data_columns == ["payload"], (
        f"{database}.{subject} StorageDescriptor.Columns={data_columns!r}, expected "
        f"['payload']: the refused predicate must name a column the catalog really holds"
    )
    assert partition_columns == ["dt"], (
        f"{database}.{subject} PartitionKeys={partition_columns!r}, expected ['dt']: "
        f"'payload' must NOT be a partition key for the refusal to mean what this check says"
    )

    # Beat 1 — positive control. The same operation, the same table, a predicate on the one
    # real partition key, returning the one partition. GetPartitions is a different operation
    # from the CreatePartition that made it.
    matched = glue.get_partitions(
        DatabaseName=database, TableName=subject, Expression=_LEGAL
    )["Partitions"]
    assert [p["Values"] for p in matched] == [["2024-01-01"]], (
        f"positive control failed: GetPartitions({subject}, {_LEGAL!r}) returned "
        f"{[p.get('Values') for p in matched]!r}, expected [['2024-01-01']]. Without this "
        f"beat, 'rejects a predicate on payload' cannot be told from 'rejects every "
        f"Expression'"
    )

    # Beat 2/3 — break exactly one thing (which column the predicate names) and demand the specific
    # code. _error RAISES on unexpected success.
    code, message = _error(
        lambda: glue.get_partitions(
            DatabaseName=database, TableName=subject, Expression=_ILLEGAL),
        f"GetPartitions({subject}, {_ILLEGAL!r})",
    )
    assert code == "InvalidInputException", (
        f"GetPartitions({subject}, {_ILLEGAL!r}) answered {code!r}, expected "
        f"'InvalidInputException': 'payload' is a real StorageDescriptor column but not a "
        f"partition key, and the Expression grammar admits partition keys only"
    )
    expected = 'Invalid partition expression!'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Beat 4 — effect absent. A refused filter must return nothing, so the unfiltered read
    # must still show exactly the one partition that existed before: the rejected call did not
    # partially apply, drop or add anything.
    survivors = glue.get_partitions(DatabaseName=database, TableName=subject)["Partitions"]
    assert [p["Values"] for p in survivors] == [["2024-01-01"]], (
        f"after the refused Expression, the unfiltered GetPartitions({subject}) returned "
        f"{[p.get('Values') for p in survivors]!r}, expected [['2024-01-01']]: the rejection "
        f"must have no effect on stored partitions"
    )

    # Beat 5 (structural, in place of a restore) — the IDENTICAL predicate on the twin, where
    # `payload` IS a partition key, is legal and matches. This is what separates a target that
    # validates "the column exists" (passes the sibling check, fails here) from one that
    # validates "the column is a partition key".
    twin_matched = glue.get_partitions(
        DatabaseName=database, TableName=twin, Expression=_ILLEGAL
    )["Partitions"]
    assert [p["Values"] for p in twin_matched] == [["2024-01-01", "hello"]], (
        f"GetPartitions({twin}, {_ILLEGAL!r}) returned "
        f"{[p.get('Values') for p in twin_matched]!r}, expected [['2024-01-01', 'hello']]: "
        f"on the twin 'payload' IS a partition key, so the identical predicate that was just "
        f"refused must now be legal — otherwise the refusal is about the name, not the role"
    )

    # Beat 6 — the identical positive control still succeeds on the subject afterwards.
    again = glue.get_partitions(
        DatabaseName=database, TableName=subject, Expression=_LEGAL
    )["Partitions"]
    assert [p["Values"] for p in again] == [["2024-01-01"]], (
        f"after the refusal, the identical positive control GetPartitions({subject}, "
        f"{_LEGAL!r}) returned {[p.get('Values') for p in again]!r}, expected "
        f"[['2024-01-01']]: the rejected call must not have poisoned the table"
    )


def _create_table(ctx, glue, database: str, label: str, *, columns, partition_keys,
                  partition_values) -> str:
    name = ctx.unique_name(f"sim2real_behav_{label}_").replace("-", "_")
    glue.create_table(
        DatabaseName=database,
        TableInput={
            "Name": name,
            "StorageDescriptor": {
                "Columns": columns,
                "Location": f"s3://example-bucket/{name}/",
            },
            "PartitionKeys": partition_keys,
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
            "Values": partition_values,
            "StorageDescriptor": {
                "Columns": columns,
                "Location": f"s3://example-bucket/{name}/{'/'.join(partition_values)}/",
            },
        },
    )
    return name


def _error(fn, label: str):
    """Return the ClientError (code, message), RAISING on unexpected success so an
    over-permissive target shows as acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"{label} succeeded; it must be refused")


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
