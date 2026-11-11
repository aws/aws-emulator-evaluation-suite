"""metadata-reads-reject-unknown-database."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "metadata-reads-reject-unknown-database"
GROUP = 'error-semantics'
SERVICES = ['athena']

def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _glue_relayed(detail, message):
    """The MetadataException text: detail, then Glue's error code and per-call Request ID, read back."""
    relayed = re.fullmatch(re.escape(detail) + r"(\w+); Request ID: ([0-9a-f-]+); Proxy: null\)", message)
    glue_code, request_id = relayed.groups() if relayed else ("<error code>", "<request id>")
    return f"{detail}{glue_code}; Request ID: {request_id}; Proxy: null)"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Glue-backed metadata reads fail on an unknown database rather than returning an empty
    result; a positive control on a created database and table proves the same reads succeed."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    catalog = "AwsDataCatalog"
    account_id = sts.get_caller_identity()["Account"]

    real_db = ctx.unique_name("sim2real_behav_db_").replace("-", "_")
    real_tbl = ctx.unique_name("sim2real_behav_tbl_").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": real_db, "Description": "sim2real athena behavioral fixture"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=real_db))
    glue.create_table(
        DatabaseName=real_db,
        TableInput={
            "Name": real_tbl,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "bigint"}],
                "Location": f"s3://sim2real-athena-fixture-{account_id}/{real_db}/{real_tbl}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )

    got_db = athena.get_database(CatalogName=catalog, DatabaseName=real_db)["Database"]
    assert got_db["Name"] == real_db, got_db
    db_names = {d["Name"] for d in athena.list_databases(CatalogName=catalog)["DatabaseList"]}
    assert real_db in db_names, db_names
    table_names = {
        t["Name"]
        for t in athena.list_table_metadata(CatalogName=catalog, DatabaseName=real_db)[
            "TableMetadataList"
        ]
    }
    assert real_tbl in table_names, table_names
    got_tbl = athena.get_table_metadata(
        CatalogName=catalog, DatabaseName=real_db, TableName=real_tbl
    )["TableMetadata"]
    assert got_tbl["Name"] == real_tbl, got_tbl

    missing_db = ctx.unique_name("sim2real-behav-db-missing-").replace("-", "_")
    missing_tbl = ctx.unique_name("sim2real-behav-tbl-missing-").replace("-", "_")

    # The MetadataException message relays the upstream Glue error with Glue's error code and
    # per-call Request ID; _glue_relayed reads those back and the rest is compared exactly.
    glue_detail = " (Service: AmazonDataCatalog; Status Code: 400; Error Code: "
    db_not_found = f"Database {missing_db} not found.{glue_detail}"
    cases = [
        ("GetDatabase", lambda: athena.get_database(CatalogName=catalog, DatabaseName=missing_db),
         db_not_found),
        (
            "ListTableMetadata",
            lambda: athena.list_table_metadata(CatalogName=catalog, DatabaseName=missing_db),
            db_not_found,
        ),
        (
            "GetTableMetadata",
            lambda: athena.get_table_metadata(
                CatalogName=catalog, DatabaseName=missing_db, TableName=missing_tbl
            ),
            f"Entity Not Found{glue_detail}",
        ),
    ]
    # Every call is graded before the verdict, so all deviations are reported at once.
    deviations = {}
    for label, fn, detail in cases:
        code, message = _error(fn)
        expected = ("MetadataException", _glue_relayed(detail, message))
        if (code, message) != expected:
            deviations[label] = (code, message)
    assert not deviations, f"expected MetadataException with Glue's relayed message from every call; deviations: {deviations}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
