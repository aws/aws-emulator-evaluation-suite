"""table-update-schema-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-update-schema-reflected"
GROUP = 'table'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """update_table replaces the StorageDescriptor and the new columns are visible immediately."""
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
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    glue.update_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "newcol", "Type": "double"}],
                "Location": "s3://example-bucket/new-data/",
            },
        },
    )

    resp = glue.get_table(DatabaseName=db_name, Name=tbl_name)
    table = resp["Table"]
    sd = table["StorageDescriptor"]
    assert [(c["Name"], c["Type"]) for c in sd["Columns"]] == [("newcol", "double")], (
        f"expected the old column replaced by exactly newcol:double, got {sd['Columns']!r}"
    )
    assert sd["Location"] == "s3://example-bucket/new-data/", (
        f"expected Location updated to the new value, got {sd.get('Location')!r}"
    )
    assert table.get("PartitionKeys", []) == [], (
        "update_table's TableInput did not repeat PartitionKeys, so the whole table "
        f"definition is replaced and partition keys must be cleared, got {table.get('PartitionKeys')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
