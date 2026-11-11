"""get-database-and-table-metadata-reflects-glue-catalog."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-database-and-table-metadata-reflects-glue-catalog"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDatabase/ListDatabases/GetTableMetadata/ListTableMetadata against a Glue-backed
    data catalog return metadata sourced live from the underlying AWS Glue Data Catalog,
    including a Glue-typed catalog created to point at the same account's Glue catalog."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    db_name = ctx.unique_name("sim2real_athena_db_").replace("-", "_")
    table_name = ctx.unique_name("sim2real_athena_tbl_").replace("-", "_")

    glue.create_database(
        DatabaseInput={"Name": db_name, "Description": "sim2real athena behavioral fixture"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_glue_db(glue, db_name))

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "bigint"},
                    {"Name": "label", "Type": "string"},
                ],
                "Location": f"s3://sim2real-athena-fixture-{account_id}/{db_name}/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )

    # Query the default Glue-backed catalog "AwsDataCatalog".
    db = athena.get_database(CatalogName="AwsDataCatalog", DatabaseName=db_name)["Database"]
    assert db["Name"] == db_name, f"expected database name {db_name!r}, got {db['Name']!r}"
    assert db["Description"] == "sim2real athena behavioral fixture", (
        f"expected description to reflect Glue, got {db['Description']!r}"
    )

    db_list = athena.list_databases(CatalogName="AwsDataCatalog")["DatabaseList"]
    assert db_name in {d["Name"] for d in db_list}, (
        f"expected {db_name!r} in ListDatabases, got {[d['Name'] for d in db_list]}"
    )

    table = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=db_name, TableName=table_name
    )["TableMetadata"]
    assert table["Name"] == table_name, f"expected table name {table_name!r}, got {table['Name']!r}"
    columns = {c["Name"]: c["Type"] for c in table["Columns"]}
    assert columns == {"id": "bigint", "label": "string"}, (
        f"expected Glue-defined columns, got {columns}"
    )

    table_list = athena.list_table_metadata(CatalogName="AwsDataCatalog", DatabaseName=db_name)[
        "TableMetadataList"
    ]
    assert table_name in {t["Name"] for t in table_list}, (
        f"expected {table_name!r} in ListTableMetadata, got {[t['Name'] for t in table_list]}"
    )

    # A named GLUE-typed data catalog pointing at the same account sources identical data.
    catalog_name = ctx.unique_name("sim2real-gluecat-")
    athena.create_data_catalog(
        Name=catalog_name,
        Type="GLUE",
        Parameters={"catalog-id": account_id},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_catalog(athena, catalog_name))

    db_via_named_catalog = athena.get_database(
        CatalogName=catalog_name, DatabaseName=db_name
    )["Database"]
    assert db_via_named_catalog["Name"] == db["Name"], (
        f"expected named-catalog database name {db['Name']!r}, "
        f"got {db_via_named_catalog['Name']!r}"
    )
    assert db_via_named_catalog["Description"] == db["Description"], (
        f"expected named-catalog description {db['Description']!r}, "
        f"got {db_via_named_catalog['Description']!r}"
    )

    table_via_named_catalog = athena.get_table_metadata(
        CatalogName=catalog_name, DatabaseName=db_name, TableName=table_name
    )["TableMetadata"]
    named_columns = {c["Name"]: c["Type"] for c in table_via_named_catalog["Columns"]}
    assert named_columns == columns, (
        f"expected named-catalog columns to match AwsDataCatalog {columns}, got {named_columns}"
    )

    # Mutating Glue directly (not through Athena) is reflected immediately on next read.
    glue.update_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "bigint"},
                    {"Name": "label", "Type": "string"},
                    {"Name": "extra", "Type": "double"},
                ],
                "Location": f"s3://sim2real-athena-fixture-{account_id}/{db_name}/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )
    refreshed = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=db_name, TableName=table_name
    )["TableMetadata"]
    refreshed_columns = {c["Name"]: c["Type"] for c in refreshed["Columns"]}
    assert refreshed_columns == {"id": "bigint", "label": "string", "extra": "double"}, (
        f"expected Athena's next read to reflect the direct Glue update, got {refreshed_columns}"
    )


def _safe_delete_glue_db(glue: Any, db_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_catalog(athena: Any, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        athena.delete_data_catalog(Name=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
