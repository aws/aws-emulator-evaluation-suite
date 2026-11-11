"""get-unfiltered-partition-metadata-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-unfiltered-partition-metadata-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without a Lake Formation grant, GetUnfilteredPartitionMetadata raises AccessDeniedException
    with the exact message for missing and real partition values alike, while GetPartition on the
    real partition succeeds.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    db_name = ctx.unique_name("sim2real-glue-db-")
    table_name = ctx.unique_name("sim2real-glue-tbl-")

    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://sim2real-glue-bucket-placeholder/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    glue.create_partition(
        DatabaseName=db_name,
        TableName=table_name,
        PartitionInput={
            "Values": ["2023"],
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://sim2real-glue-bucket-placeholder/data/year=2023/",
            },
        },
    )
    ctx.on_cleanup(
        lambda: glue.delete_partition(
            DatabaseName=db_name, TableName=table_name, PartitionValues=["2023"]
        )
    )

    # Positive control: our ordinary IAM credentials are fine and see the real partition via
    # the standard (non-Lake-Formation-gated) GetPartition call.
    got = glue.get_partition(
        DatabaseName=db_name, TableName=table_name, PartitionValues=["2023"]
    )
    assert got["Partition"]["Values"] == ["2023"], (
        f"positive control failed: expected ['2023'], got {got['Partition']['Values']}"
    )

    # A partition whose values do not exist is rejected, not served as an empty/successful shape.
    code, message = _error(
        lambda: glue.get_unfiltered_partition_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            PartitionValues=["9999"],
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ''
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The real partition, still ungranted in Lake Formation, is rejected the same way -- an
    # emulator that aliases this credential-vending API straight to GetPartition (ignoring Lake
    # Formation authorization) would incorrectly return it here instead.
    code, message = _error(
        lambda: glue.get_unfiltered_partition_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            PartitionValues=["2023"],
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ''
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

