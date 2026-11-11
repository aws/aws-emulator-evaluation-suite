"""get-unfiltered-table-metadata-nonexistent-table-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-unfiltered-table-metadata-nonexistent-table-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Without a Lake Formation grant, GetUnfilteredTableMetadata raises AccessDeniedException with
    the exact message for a missing and a real table alike, while GetTable on the real table
    succeeds.
    """
    glue = ctx.client("glue")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    db_name = ctx.unique_name("sim2real-glue-db-")
    table_name = ctx.unique_name("sim2real-glue-tbl-")
    bogus_table_name = ctx.unique_name("sim2real-glue-missing-")

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
            "PartitionKeys": [],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    # Positive control: our ordinary IAM credentials are fine and see the real table via the
    # standard (non-Lake-Formation-gated) GetTable call.
    got = glue.get_table(DatabaseName=db_name, Name=table_name)
    assert got["Table"]["Name"] == table_name

    # A nonexistent table is rejected, not served as an empty/successful shape.
    code, message = _error(
        lambda: glue.get_unfiltered_table_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            Name=bogus_table_name,
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The real table, still ungranted in Lake Formation, is rejected the same way -- an
    # emulator that aliases this credential-vending API straight to GetTable (ignoring Lake
    # Formation authorization) would incorrectly return the table here instead.
    code, message = _error(
        lambda: glue.get_unfiltered_table_metadata(
            CatalogId=account_id,
            DatabaseName=db_name,
            Name=table_name,
            SupportedPermissionTypes=["COLUMN_PERMISSION"],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = ""
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

