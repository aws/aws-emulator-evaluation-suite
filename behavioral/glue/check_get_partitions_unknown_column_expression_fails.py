"""get-partitions-unknown-column-expression-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-partitions-unknown-column-expression-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPartitions filtering on a column that is not a partition key raises InvalidInputException
    with the exact message, while a filter on the partition key "dt" succeeds.
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

    control = glue.get_partitions(
        DatabaseName=db_name,
        TableName=tbl_name,
        Expression="dt = 'control'",
    )
    assert "Partitions" in control, (
        f"expected get_partitions filtering on the real partition key 'dt' to succeed, "
        f"got {control!r}"
    )

    try:
        glue.get_partitions(
            DatabaseName=db_name,
            TableName=tbl_name,
            Expression="not_a_partition_key = 'x'",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError("get_partitions accepted the Expression; it must be refused")
    assert code == "InvalidInputException", (
        f"expected InvalidInputException filtering on a non-partition column, got {code}"
    )
    expected = 'Invalid partition expression!'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
