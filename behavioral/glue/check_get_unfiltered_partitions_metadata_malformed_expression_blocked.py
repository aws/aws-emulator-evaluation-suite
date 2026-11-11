"""get-unfiltered-partitions-metadata-malformed-expression-blocked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-unfiltered-partitions-metadata-malformed-expression-blocked"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUnfilteredPartitionsMetadata denies an ungranted caller before parsing the Expression.

    Plain GetPartitions is the control: it filters a valid expression and rejects the malformed one.
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

    for year in ("2023", "2024"):
        glue.create_partition(
            DatabaseName=db_name,
            TableName=table_name,
            PartitionInput={
                "Values": [year],
                "StorageDescriptor": {
                    "Columns": [{"Name": "col1", "Type": "string"}],
                    "Location": f"s3://sim2real-glue-bucket-placeholder/data/year={year}/",
                },
            },
        )
        ctx.on_cleanup(
            lambda year=year: glue.delete_partition(
                DatabaseName=db_name, TableName=table_name, PartitionValues=[year]
            )
        )

    resp = glue.get_partitions(
        DatabaseName=db_name, TableName=table_name, Expression="year = '2023'"
    )
    values = [p["Values"] for p in resp["Partitions"]]
    assert values == [["2023"]], f"expected only the 2023 partition, got {values}"

    code, message = _error(
        lambda: glue.get_partitions(
            DatabaseName=db_name, TableName=table_name, Expression="year = AND (((",
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    expected = "Invalid partition expression!"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Lake Formation authorization runs before Expression parsing.
    code, message = _error(
        lambda: glue.get_unfiltered_partitions_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            Expression="year = AND (((",
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A well-formed expression is denied too: this is not an alias of GetPartitions.
    code, message = _error(
        lambda: glue.get_unfiltered_partitions_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            TableName=table_name,
            Expression="year = '2023'",
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

