"""partition-batch-create-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partition-batch-create-partial-failure"
GROUP = 'partition'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """batch_create_partition reports per-entry errors for duplicates without failing the whole batch."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
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

    # Pre-create one partition so a subsequent batch that re-includes it is a duplicate.
    glue.create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInput={"Values": ["2020"]},
    )

    resp = glue.batch_create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInputList=[
            {"Values": ["2020"]},  # duplicate -> should error
            {"Values": ["2021"]},  # new -> should succeed
        ],
    )

    errors = resp.get("Errors", [])
    assert len(errors) == 1, f"expected exactly one per-entry error, got {errors}"
    assert errors[0]["PartitionValues"] == ["2020"], (
        f"expected the error to identify the duplicate entry ['2020'], got {errors[0]}"
    )
    assert errors[0]["ErrorDetail"]["ErrorCode"] == "AlreadyExistsException", (
        f"expected a duplicate partition to be reported as AlreadyExistsException, got {errors[0]}"
    )
    expected_message = "Partition already exists."
    assert errors[0]["ErrorDetail"].get("ErrorMessage") == expected_message, (
        f"expected the duplicate's ErrorMessage {expected_message!r}, got {errors[0]['ErrorDetail']}"
    )

    # The non-duplicate entry must still have been created.
    resp2 = glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2021"])
    assert resp2["Partition"]["Values"] == ["2021"], (
        f"expected the non-duplicate entry to have been created despite the batch's partial "
        f"failure, got {resp2['Partition']['Values']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
