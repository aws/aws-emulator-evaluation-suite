"""partition-update-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partition-update-reflected"
GROUP = 'partition'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """update_partition replaces the partition's storage descriptor in place."""
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

    glue.create_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionInput={
            "Values": ["2022"],
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/year=2022/",
                "Compressed": True,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            },
        },
    )

    # Update's StorageDescriptor omits Compressed/InputFormat: proves update_partition
    # replaces the storage descriptor wholesale rather than merging field-by-field.
    glue.update_partition(
        DatabaseName=db_name,
        TableName=tbl_name,
        PartitionValueList=["2022"],
        PartitionInput={
            "Values": ["2022"],
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/relocated/year=2022/",
            },
        },
    )

    part = glue.get_partition(
        DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2022"]
    )["Partition"]
    assert part["Values"] == ["2022"], part
    sd = part["StorageDescriptor"]
    assert sd["Location"] == "s3://example-bucket/relocated/year=2022/", sd["Location"]
    assert not sd.get("Compressed"), (
        f"Compressed carried over from the pre-update descriptor instead of being replaced: {sd}"
    )
    assert not sd.get("InputFormat"), (
        f"InputFormat carried over from the pre-update descriptor instead of being replaced: {sd}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
