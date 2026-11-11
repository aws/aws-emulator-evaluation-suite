"""reject-get-nonexistent-table-version."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-get-nonexistent-table-version"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """get_table_version with a VersionId that was never produced must be rejected,
    while the version that create_table actually produced remains readable through
    the identical call — otherwise a target that rejects every VersionId would pass."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-behav-check": CHECK})
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

    real_versions = [
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    ]
    assert real_versions, "expected create_table to produce at least one table version"
    real_version_id = real_versions[0]

    # Positive control: the version create_table actually produced is readable through
    # the same call the rejection below exercises.
    control = glue.get_table_version(
        DatabaseName=db_name, TableName=tbl_name, VersionId=real_version_id
    )["TableVersion"]
    assert control["Table"]["Name"] == tbl_name, (
        f"expected get_table_version({real_version_id!r}) to return table {tbl_name!r}, "
        f"got {control['Table'].get('Name')!r}"
    )

    code, message = _error(
        lambda: glue.get_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId="9999")
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == "Version not found.", message


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
