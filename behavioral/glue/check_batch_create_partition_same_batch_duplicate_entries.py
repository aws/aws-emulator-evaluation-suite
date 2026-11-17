"""batch-create-partition-same-batch-duplicate-entries."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-partition-same-batch-duplicate-entries"
GROUP = 'partition'
SERVICES = ['glue']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchCreatePartition with the same Values listed twice in one request, with neither
    partition pre-existing, creates the partition once and reports the repeat entry as a
    per-entry AlreadyExistsException with its exact message.
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
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    # Positive control: a batch of two distinct, never-seen values succeeds with no errors.
    control = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[{"Values": ["2030"]}, {"Values": ["2031"]}],
    )
    assert control.get("Errors", []) == [], (
        f"expected no per-entry errors for two distinct new partitions, got {control.get('Errors')}"
    )

    resp = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[{"Values": ["2032"]}, {"Values": ["2032"]}],
    )
    errors = resp.get("Errors", [])
    assert len(errors) == 1, (
        f"a batch listing ['2032'] twice must fail the repeat entry alone, got {len(errors)}: {errors}"
    )
    assert errors[0]["PartitionValues"] == ["2032"], (
        f"the error must identify the repeated entry by its Values, got {errors[0]}"
    )
    assert errors[0]["ErrorDetail"]["ErrorCode"] == "AlreadyExistsException", (
        f"the repeat entry must be reported as AlreadyExistsException, got {errors[0]}"
    )
    expected_message = "Partition already exists."
    assert errors[0]["ErrorDetail"].get("ErrorMessage") == expected_message, (
        f"expected the repeat entry's ErrorMessage {expected_message!r}, got {errors[0]}"
    )

    listed = sorted(
        tuple(p["Values"])
        for p in glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)["Partitions"]
    )
    assert listed == [("2030",), ("2031",), ("2032",)], (
        f"expected the control pair plus exactly one '2032' partition, got {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
