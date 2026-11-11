"""create-table-partition-key-overlapping-column-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-table-partition-key-overlapping-column-accepted"
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


def _col_type(columns, name):
    matches = [c["Type"] for c in columns if c["Name"] == name]
    assert len(matches) == 1, f"expected exactly one column named {name!r}, got {matches}"
    return matches[0]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable accepts a PartitionKeys name that also appears in StorageDescriptor.Columns and
    stores both declarations verbatim, even when their types disagree; Glue does not cross-validate.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    # Case 1: 'dt' names both a data column and a partition key, with the same declared type.
    same_type_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": same_type_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage(
                [{"Name": "id", "Type": "bigint"}, {"Name": "dt", "Type": "string"}]
            ),
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=same_type_name))

    same_type = glue.get_table(DatabaseName=db_name, Name=same_type_name)["Table"]
    same_type_columns = [c["Name"] for c in same_type["StorageDescriptor"]["Columns"]]
    same_type_keys = [k["Name"] for k in same_type["PartitionKeys"]]
    assert same_type_columns == ["id", "dt"], (
        f"overlapping-name table must keep 'dt' in Columns verbatim, got {same_type_columns}"
    )
    assert same_type_keys == ["dt"], (
        f"overlapping-name table must keep 'dt' in PartitionKeys verbatim, got {same_type_keys}"
    )

    # Case 2: the two declarations of 'dt' disagree on type. Real Glue does not reconcile them --
    # each side keeps exactly the type it was given, independent of the other.
    conflict_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": conflict_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage(
                [{"Name": "id", "Type": "bigint"}, {"Name": "dt", "Type": "string"}]
            ),
            "PartitionKeys": [{"Name": "dt", "Type": "int"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=conflict_name))

    conflict = glue.get_table(DatabaseName=db_name, Name=conflict_name)["Table"]
    conflict_column_type = _col_type(conflict["StorageDescriptor"]["Columns"], "dt")
    conflict_key_type = _col_type(conflict["PartitionKeys"], "dt")
    assert conflict_column_type == "string", (
        f"Columns['dt'] must keep its declared type 'string', got {conflict_column_type!r}"
    )
    assert conflict_key_type == "int", (
        "PartitionKeys['dt'] must keep its declared type 'int' independent of Columns, got "
        f"{conflict_key_type!r}"
    )

    # Independent read at a different operation: both tables are listed, neither was refused.
    listed = {t["Name"] for t in glue.get_tables(DatabaseName=db_name)["TableList"]}
    assert listed == {same_type_name, conflict_name}, (
        f"both accepted tables must be listed, got {listed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
