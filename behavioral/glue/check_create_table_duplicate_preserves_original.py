"""create-table-duplicate-preserves-original."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-table-duplicate-preserves-original"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateTable raises AlreadyExistsException ("Table already exists.") and leaves
    the table's columns, Description, VersionId and version list unchanged; a new name is created
    normally.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    original = {
        "Name": tbl_name,
        "Description": "sim2real original v1",
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": _storage([{"Name": "id", "Type": "bigint"}]),
    }
    glue.create_table(DatabaseName=db_name, TableInput=original)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    before = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    versions_before = len(
        glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    )

    conflicting = {
        "Name": tbl_name,
        "Description": "sim2real conflicting v2",
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": _storage([{"Name": "other", "Type": "string"}]),
    }
    try:
        glue.create_table(DatabaseName=db_name, TableInput=conflicting)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "AlreadyExistsException", (
        f"CreateTable on an existing table name must raise AlreadyExistsException, got {code}"
    )
    assert message == "Table already exists.", f"unexpected AlreadyExistsException message {message!r}"

    # Effect absent: schema, description and version count are exactly as before.
    after = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert [c["Name"] for c in after["StorageDescriptor"]["Columns"]] == ["id"], (
        f"rejected CreateTable silently overwrote the schema: {after['StorageDescriptor']}"
    )
    assert after["Description"] == "sim2real original v1", (
        f"rejected CreateTable overwrote the description: {after['Description']!r}"
    )
    assert after["VersionId"] == before["VersionId"], (
        f"rejected CreateTable moved VersionId {before['VersionId']} -> {after['VersionId']}"
    )
    versions_after = len(
        glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    )
    assert versions_after == versions_before, (
        f"rejected CreateTable minted a table version: {versions_before} -> {versions_after}"
    )

    # Control: the very same TableInput is accepted under a free name, so the rejection was
    # about the name collision and not about the payload.
    other_name = ctx.unique_name("sim2real-behav-tbl-")
    accepted = dict(conflicting, Name=other_name)
    glue.create_table(DatabaseName=db_name, TableInput=accepted)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=other_name))
    control = glue.get_table(DatabaseName=db_name, Name=other_name)["Table"]
    assert [c["Name"] for c in control["StorageDescriptor"]["Columns"]] == ["other"], (
        f"control table did not take the second schema: {control['StorageDescriptor']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
