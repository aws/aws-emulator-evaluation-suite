"""metadata-exception-for-invalid-catalog."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metadata-exception-for-invalid-catalog"
GROUP = "error-semantics"
SERVICES = ["athena"]

_REAL_CATALOG = "AwsDataCatalog"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get/ListDatabases and Get/ListTableMetadata on a nonexistent catalog raise
    InvalidRequestException (not MetadataException), after the same calls succeed on the real one."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")

    real_db = ctx.unique_name("sim2real_athena_db_").replace("-", "_")
    real_table = ctx.unique_name("sim2real_athena_tbl_").replace("-", "_")
    fake_catalog = ctx.unique_name("sim2real-nocatalog-")

    glue.create_database(
        DatabaseInput={"Name": real_db, "Description": "sim2real invalid-catalog behavioral fixture"}
    )
    ctx.on_cleanup(lambda: _safe_delete_glue_db(glue, real_db))

    glue.create_table(
        DatabaseName=real_db,
        TableInput={
            "Name": real_table,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "bigint"}],
                "Location": f"s3://sim2real-athena-fixture-placeholder/{real_db}/{real_table}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )

    # Positive control: the real catalog, database and table all resolve.
    db = athena.get_database(CatalogName=_REAL_CATALOG, DatabaseName=real_db)["Database"]
    assert db["Name"] == real_db, f"GetDatabase: expected {real_db}, got {db['Name']}"

    db_list = athena.list_databases(CatalogName=_REAL_CATALOG)["DatabaseList"]
    assert real_db in {d["Name"] for d in db_list}, f"ListDatabases: {real_db} missing from {db_list}"

    table = athena.get_table_metadata(
        CatalogName=_REAL_CATALOG, DatabaseName=real_db, TableName=real_table
    )["TableMetadata"]
    assert table["Name"] == real_table, f"GetTableMetadata: expected {real_table}, got {table['Name']}"

    table_list = athena.list_table_metadata(CatalogName=_REAL_CATALOG, DatabaseName=real_db)[
        "TableMetadataList"
    ]
    assert real_table in {t["Name"] for t in table_list}, (
        f"ListTableMetadata: {real_table} missing from {table_list}"
    )

    # Negative: only the catalog name changes.
    expected = ("InvalidRequestException", f"Cannot find catalog {fake_catalog}.")
    got = _error(lambda: athena.get_database(CatalogName=fake_catalog, DatabaseName=real_db))
    assert got == expected, f"GetDatabase: expected {expected}, got {got}"

    got = _error(lambda: athena.list_databases(CatalogName=fake_catalog))
    assert got == expected, f"ListDatabases: expected {expected}, got {got}"

    got = _error(
        lambda: athena.get_table_metadata(
            CatalogName=fake_catalog, DatabaseName=real_db, TableName=real_table
        )
    )
    assert got == expected, f"GetTableMetadata: expected {expected}, got {got}"

    got = _error(lambda: athena.list_table_metadata(CatalogName=fake_catalog, DatabaseName=real_db))
    assert got == expected, f"ListTableMetadata: expected {expected}, got {got}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


def _safe_delete_glue_db(glue: Any, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
