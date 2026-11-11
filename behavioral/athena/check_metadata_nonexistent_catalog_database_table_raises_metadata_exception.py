"""metadata-nonexistent-catalog-database-table-raises-metadata-exception."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metadata-nonexistent-catalog-database-table-raises-metadata-exception"
GROUP = "error-semantics"
SERVICES = ["athena"]

_DEFAULT_CATALOG = "AwsDataCatalog"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In the default Glue catalog, metadata reads of a nonexistent database fail with
    MetadataException (after a positive control on a real database and table), while an unknown
    catalog fails with InvalidRequestException."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")

    real_db = ctx.unique_name("sim2real_athena_md_db_").replace("-", "_")
    real_table = ctx.unique_name("sim2real_athena_md_tbl_").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": real_db, "Description": "sim2real metadata-exception fixture"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_glue_db(glue, real_db))
    glue.create_table(
        DatabaseName=real_db,
        TableInput={
            "Name": real_table,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "bigint"}],
                "Location": f"s3://sim2real-athena-metadata-fixture/{real_db}/{real_table}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"},
            },
        },
    )

    got_db = athena.get_database(CatalogName=_DEFAULT_CATALOG, DatabaseName=real_db)["Database"]
    assert got_db["Name"] == real_db, f"positive control GetDatabase: expected {real_db}, got {got_db}"
    got_table = athena.get_table_metadata(
        CatalogName=_DEFAULT_CATALOG, DatabaseName=real_db, TableName=real_table
    )["TableMetadata"]
    assert got_table["Name"] == real_table, (
        f"positive control GetTableMetadata: expected {real_table}, got {got_table}"
    )
    real_table_names = {
        t["Name"]
        for t in athena.list_table_metadata(CatalogName=_DEFAULT_CATALOG, DatabaseName=real_db)[
            "TableMetadataList"
        ]
    }
    assert real_table in real_table_names, (
        f"positive control ListTableMetadata: expected {real_table} in {real_table_names}"
    )

    bogus_db = ctx.unique_name("sim2real-nonexistent-db-")
    bogus_table = ctx.unique_name("sim2real-nonexistent-tbl-")
    bogus_catalog = ctx.unique_name("sim2real-nonexistent-catalog-")

    # message varies: the MetadataException message relays the upstream Glue error and
    # embeds Glue's per-call Request ID, which the check cannot know, so only the code is graded.
    code, _ = _error(
        lambda: athena.get_database(CatalogName=_DEFAULT_CATALOG, DatabaseName=bogus_db)
    )
    assert code == "MetadataException", f"GetDatabase on nonexistent db: expected MetadataException, got {code}"

    # message varies: embeds the upstream Glue Request ID (see above).
    code, _ = _error(
        lambda: athena.get_table_metadata(
            CatalogName=_DEFAULT_CATALOG, DatabaseName=bogus_db, TableName=bogus_table
        )
    )
    assert code == "MetadataException", (
        f"GetTableMetadata on nonexistent db: expected MetadataException, got {code}"
    )

    # message varies: embeds the upstream Glue Request ID (see above).
    code, _ = _error(
        lambda: athena.list_table_metadata(CatalogName=_DEFAULT_CATALOG, DatabaseName=bogus_db)
    )
    assert code == "MetadataException", (
        f"ListTableMetadata on nonexistent db: expected MetadataException, got {code}"
    )

    # An unknown catalog is rejected at request validation, not by the metastore.
    got = _error(lambda: athena.list_databases(CatalogName=bogus_catalog))
    expected = ("InvalidRequestException", f"Cannot find catalog {bogus_catalog}.")
    assert got == expected, f"ListDatabases on nonexistent catalog: expected {expected}, got {got}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_glue_db(glue, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
