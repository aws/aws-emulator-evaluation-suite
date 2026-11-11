"""partition-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partition-create-get-delete"
GROUP = 'partition'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_partition -> get_partition reflects the values -> delete_partition removes it,
    the dead partition id rejects both a read and a mutation, and it is reusable."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")  # has a single "year" partition key
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

    def _create_partition(location):
        glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": ["2023"],
                "StorageDescriptor": {
                    "Columns": [{"Name": "col1", "Type": "string"}],
                    "Location": location,
                },
            },
        )

    _create_partition("s3://example-bucket/data/year=2023/")

    resp = glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023"])
    assert resp["Partition"]["Values"] == ["2023"], (
        f"expected get_partition to reflect Values=['2023'], got {resp['Partition']['Values']}"
    )

    glue.delete_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023"])

    expected_message = "Cannot find partition."
    code, message = _error_code(
        lambda: glue.get_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023"])
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == expected_message, f"expected GetPartition message {expected_message!r}, got {message!r}"

    expected_message = "Partition [2023] not found"
    update_code, update_message = _error_code(
        lambda: glue.update_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionValueList=["2023"],
            PartitionInput={
                "Values": ["2023"],
                "StorageDescriptor": {
                    "Columns": [{"Name": "col1", "Type": "string"}],
                    "Location": "s3://example-bucket/data/year=2023-moved/",
                },
            },
        )
    )
    assert update_code == "EntityNotFoundException", (
        f"a deleted partition must reject a mutation with EntityNotFoundException, got {update_code}"
    )
    assert update_message == expected_message, (
        f"expected UpdatePartition message {expected_message!r}, got {update_message!r}"
    )

    # the identifier is reusable: recreating with the same Values must succeed and reflect the new data
    _create_partition("s3://example-bucket/data/year=2023-reused/")
    ctx.on_cleanup(
        lambda: glue.delete_partition(DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023"])
    )
    reused = glue.get_partition(
        DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2023"]
    )["Partition"]
    assert reused["StorageDescriptor"]["Location"] == "s3://example-bucket/data/year=2023-reused/", (
        "recreating partition ['2023'] after delete should succeed and reflect the new location, "
        f"got {reused['StorageDescriptor']['Location']}"
    )


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
