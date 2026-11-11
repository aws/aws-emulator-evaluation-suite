"""get-partitions-malformed-expression-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-partitions-malformed-expression-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPartitions with a syntactically invalid Expression raises InvalidInputException with the
    exact message, while a well-formed Expression returns the one created partition.
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
            "Values": ["2024-01-01"],
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/dt=2024-01-01/",
            },
        },
    )
    ctx.on_cleanup(
        lambda: glue.delete_partition(
            DatabaseName=db_name, TableName=tbl_name, PartitionValues=["2024-01-01"]
        )
    )

    # Positive control: a well-formed Expression against the real partition succeeds and
    # returns exactly it, proving credentials, table state and get_partitions itself are
    # healthy before the malformed-expression rejection is asserted below.
    resp = glue.get_partitions(
        DatabaseName=db_name, TableName=tbl_name, Expression="dt = '2024-01-01'"
    )
    values = [p["Values"] for p in resp["Partitions"]]
    assert values == [["2024-01-01"]], f"expected the one created partition, got {values}"

    try:
        glue.get_partitions(
            DatabaseName=db_name,
            TableName=tbl_name,
            Expression="dt >>>> not a valid predicate",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError("get_partitions accepted the Expression; it must be refused")
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for a malformed partition Expression, got {code}"
    )
    expected = 'Invalid partition expression!'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
