"""update-table-skip-archive-suppresses-version."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-table-skip-archive-suppresses-version"
GROUP = 'table'
SERVICES = ['glue']


def _storage(columns):
    return {
        "Columns": columns,
        "Location": "s3://example-bucket/data/",
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
        },
    }


def _version_count(glue, db_name, tbl_name):
    return len(
        glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTable adds a table version by default and adds none with SkipArchive=True, while the
    live table still takes the skipped update's columns; high-churn writers rely on this to stay
    under the version limit.
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
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    at_create = _version_count(glue, db_name, tbl_name)
    assert at_create == 1, f"a freshly created table must have 1 version, got {at_create}"

    # Baseline leg: the default (archiving) update adds a version row.
    glue.update_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage(
                [{"Name": "id", "Type": "bigint"}, {"Name": "amount", "Type": "double"}]
            ),
        },
    )
    archived = _version_count(glue, db_name, tbl_name)
    assert archived == at_create + 1, (
        f"UpdateTable without SkipArchive must archive the previous definition: "
        f"{at_create} -> {archived}"
    )

    # SkipArchive leg: the schema changes but no version row is added.
    glue.update_table(
        DatabaseName=db_name,
        SkipArchive=True,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage(
                [
                    {"Name": "id", "Type": "bigint"},
                    {"Name": "amount", "Type": "double"},
                    {"Name": "label", "Type": "string"},
                ]
            ),
        },
    )
    skipped = _version_count(glue, db_name, tbl_name)
    assert skipped == archived, (
        f"UpdateTable with SkipArchive=True must not add a table version: "
        f"{archived} -> {skipped}"
    )

    live = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert [c["Name"] for c in live["StorageDescriptor"]["Columns"]] == [
        "id",
        "amount",
        "label",
    ], (
        "the SkipArchive update must still be applied to the live table, got "
        f"{live['StorageDescriptor']['Columns']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
