"""delete-current-table-version-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-current-table-version-rejected"
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


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableVersion refuses the table's current version with InvalidInputException and changes
    nothing, while archived versions stay deletable; once superseded, that version deletes too."""
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

    # Two updates → three version rows (the original plus two archives).
    for extra in ({"Name": "amount", "Type": "double"}, {"Name": "label", "Type": "string"}):
        cols = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"][
            "StorageDescriptor"
        ]["Columns"]
        glue.update_table(
            DatabaseName=db_name,
            TableInput={
                "Name": tbl_name,
                "TableType": "EXTERNAL_TABLE",
                "StorageDescriptor": _storage(list(cols) + [extra]),
            },
        )

    current = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["VersionId"]
    before = sorted(
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)[
            "TableVersions"
        ]
    )
    assert len(before) == 3, f"expected 3 table versions after 2 updates, got {before}"
    assert current in before, f"current VersionId {current} missing from {before}"
    archived = [v for v in before if v != current]

    refused = _refusal(
        lambda: glue.delete_table_version(
            DatabaseName=db_name, TableName=tbl_name, VersionId=current
        )
    )
    assert refused == ("InvalidInputException", "VersionId cannot be equal to the latest."), (
        f"deleting the current table version {current} must be refused with "
        f"InvalidInputException, got {refused}"
    )

    # Effect absent: the current version is still there and still resolvable.
    after_reject = sorted(
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)[
            "TableVersions"
        ]
    )
    assert after_reject == before, (
        f"refused DeleteTableVersion must not change the version set: {before} -> {after_reject}"
    )
    live = glue.get_table_version(
        DatabaseName=db_name, TableName=tbl_name, VersionId=current
    )["TableVersion"]
    assert [c["Name"] for c in live["Table"]["StorageDescriptor"]["Columns"]] == [
        "id",
        "amount",
        "label",
    ], f"current version schema was altered by the refused delete: {live}"

    # Control: an ARCHIVED version really is deletable, so the refusal above was
    # specific to the current version and not a blanket failure of the operation.
    victim = archived[0]
    glue.delete_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=victim)
    after_control = sorted(
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)[
            "TableVersions"
        ]
    )
    assert victim not in after_control, (
        f"archived version {victim} should be deletable, still present in {after_control}"
    )
    assert current in after_control, (
        f"current version {current} disappeared while pruning {victim}: {after_control}"
    )
    victim_code = _refusal(
        lambda: glue.get_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=victim)
    )
    assert victim_code == ("EntityNotFoundException", "Table version not found."), (
        f"GetTableVersion on the deleted archived version {victim} must fail with "
        f"EntityNotFoundException, got {victim_code}"
    )

    # Restore: once superseded, the VersionId refused above is no longer current and deletes.
    cols = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["StorageDescriptor"][
        "Columns"
    ]
    glue.update_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": _storage(list(cols) + [{"Name": "flag", "Type": "boolean"}]),
        },
    )
    new_current = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["VersionId"]
    assert new_current != current, f"expected a new current version, still {current}"

    glue.delete_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=current)
    after_restore = {
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)[
            "TableVersions"
        ]
    }
    assert current not in after_restore, (
        f"once superseded, the formerly-current version {current} must become deletable, "
        f"still present in {after_restore}"
    )
    assert new_current in after_restore, (
        f"the new current version {new_current} must survive its predecessor's deletion: "
        f"{after_restore}"
    )
    restored_code = _refusal(
        lambda: glue.get_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=current)
    )
    assert restored_code == ("EntityNotFoundException", "Table version not found."), (
        f"GetTableVersion on the deleted former-current version {current} must fail with "
        f"EntityNotFoundException, got {restored_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
