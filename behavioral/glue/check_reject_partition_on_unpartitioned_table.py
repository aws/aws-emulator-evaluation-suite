"""reject-partition-on-unpartitioned-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-partition-on-unpartitioned-table"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_partition on a table declared with no PartitionKeys must be rejected, while the
    identical call against a table that does declare a partition key succeeds."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    # positive control: the same call succeeds against a table that declares a partition key,
    # so the rejection below is about the absent PartitionKeys, not create_partition in general.
    ctrl_tbl_name = ctx.unique_name("sim2real-behav-ctrl-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": ctrl_tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "c", "Type": "string"}],
                "Location": "s3://example-bucket/data/ctrl/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=ctrl_tbl_name))
    glue.create_partition(
        DatabaseName=db_name,
        TableName=ctrl_tbl_name,
        PartitionInput={
            "Values": ["2023"],
            "StorageDescriptor": {
                "Columns": [{"Name": "c", "Type": "string"}],
                "Location": "s3://example-bucket/data/ctrl/year=2023/",
            },
        },
    )
    ctrl_partition = glue.get_partition(
        DatabaseName=db_name, TableName=ctrl_tbl_name, PartitionValues=["2023"]
    )["Partition"]
    assert ctrl_partition["Values"] == ["2023"], (
        f"positive control: expected the partition to be visible, got {ctrl_partition}"
    )

    # subject: a table with a location (so the rejection below is isolated to the missing
    # PartitionKeys, not confounded with the "no location" rejection the control avoids)
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "c", "Type": "string"}],
                "Location": "s3://example-bucket/data/subject/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    code, message = _error(
        lambda: glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": ["2023"],
                "StorageDescriptor": {
                    "Columns": [{"Name": "c", "Type": "string"}],
                    "Location": "s3://example-bucket/data/subject/year=2023/",
                },
            },
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    assert message == "Cannot create partitions in table without partition keys", message

    # effect absent: an independent read confirms no partition was created on the subject table
    partitions = glue.get_partitions(DatabaseName=db_name, TableName=tbl_name)["Partitions"]
    assert partitions == [], f"expected no partitions on the unpartitioned table, got {partitions}"


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
