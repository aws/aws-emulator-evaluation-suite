"""create-partition-duplicate-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-partition-duplicate-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePartition with the Values of an existing partition raises AlreadyExistsException
    ("Partition already exists.") and keeps the original Location; after DeletePartition
    (GetPartition: EntityNotFoundException) the original call succeeds again.
    """
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
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    values = ["2024-03-01"]
    original_location = "s3://example-bucket/data/dt=2024-03-01/"
    partition_input = {
        "Values": values,
        "StorageDescriptor": {
            "Columns": [{"Name": "col1", "Type": "string"}],
            "Location": original_location,
        },
    }
    # Positive control: the partition does not exist yet, so this must succeed.
    glue.create_partition(DatabaseName=db_name, TableName=tbl_name, PartitionInput=partition_input)
    ctx.on_cleanup(lambda: _delete_partition_ignoring_not_found(glue, db_name, tbl_name, values))

    # Break: an identical Values with a DIFFERENT StorageDescriptor.
    clobber_location = "s3://example-bucket/data/dt=2024-03-01-clobber/"
    try:
        glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": values,
                "StorageDescriptor": {
                    "Columns": [{"Name": "col1", "Type": "string"}],
                    "Location": clobber_location,
                },
            },
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError("expected the duplicate CreatePartition to be rejected, but it succeeded")
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}"
    assert message == "Partition already exists.", f"unexpected CreatePartition message: {message!r}"

    # Effect absent, via an independent read: exactly one partition for these Values, and its
    # Location is still the original one, not the rejected duplicate's.
    partitions = glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)["Partitions"]
    matching = [p for p in partitions if p["Values"] == values]
    assert len(matching) == 1, f"expected exactly 1 partition for {values}, found {len(matching)}"
    stored_location = matching[0]["StorageDescriptor"]["Location"]
    assert stored_location == original_location, (
        f"expected the original location {original_location!r} to survive the rejected "
        f"duplicate create, got {stored_location!r}"
    )

    # Restore: remove the partition that made the duplicate a conflict, and prove it is gone via
    # an independent read.
    glue.delete_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=values)
    try:
        glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=values)
    except ClientError as exc:
        delete_code = exc.response["Error"]["Code"]
        delete_message = exc.response["Error"].get("Message")
    else:
        raise AssertionError("expected GetPartition after delete to be rejected, but it succeeded")
    assert delete_code == "EntityNotFoundException", (
        f"expected an independent read to report EntityNotFoundException after delete, "
        f"got {delete_code}"
    )
    assert delete_message == "Cannot find partition.", f"unexpected GetPartition message: {delete_message!r}"

    # The identical original call now succeeds, proving the rejection was tied to the
    # pre-existing partition and not to these Values or this Location in general.
    glue.create_partition(DatabaseName=db_name, TableName=tbl_name, PartitionInput=partition_input)
    restored = glue.get_partition(
        DatabaseName=db_name, TableName=tbl_name, PartitionValues=values
    )["Partition"]
    restored_location = restored["StorageDescriptor"]["Location"]
    assert restored_location == original_location, (
        f"expected the restored partition's location to be {original_location!r}, "
        f"got {restored_location!r}"
    )


def _delete_partition_ignoring_not_found(glue, db_name, tbl_name, values) -> None:
    try:
        glue.delete_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=values)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
