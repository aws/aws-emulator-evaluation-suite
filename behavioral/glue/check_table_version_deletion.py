"""table-version-deletion."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "table-version-deletion"
GROUP = 'table'
SERVICES = ['glue']

def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """delete_table_version / batch_delete_table_version prune history without touching current."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")

    def put(location, create=False):
        table_input = {
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}],
                "Location": location,
            },
        }
        if create:
            glue.create_table(DatabaseName=db_name, TableInput=table_input)
        else:
            glue.update_table(DatabaseName=db_name, TableInput=table_input)

    put("s3://example-bucket/v1/", create=True)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))
    put("s3://example-bucket/v2/")
    put("s3://example-bucket/v3/")
    put("s3://example-bucket/v4/")

    versions = glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    assert len(versions) == 4, f"expected 4 versions, got {len(versions)}"
    ids = sorted((v["VersionId"] for v in versions), key=int)
    current_id = ids[-1]

    glue.delete_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=ids[0])
    after_single = {
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    }
    assert ids[0] not in after_single, "delete_table_version did not remove the version"
    assert current_id in after_single, "delete_table_version must not remove the current version"

    deleted_get_code, deleted_get_message = _refusal(
        lambda: glue.get_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=ids[0])
    )
    assert deleted_get_code == "EntityNotFoundException", (
        f"get_table_version on a version deleted by delete_table_version must fail with "
        f"EntityNotFoundException, got {deleted_get_code}"
    )
    assert deleted_get_message == "Table version not found.", deleted_get_message

    resp = glue.batch_delete_table_version(
        DatabaseName=db_name, TableName=tbl_name, VersionIds=[ids[1], "9999"]
    )
    errors = {e["VersionId"]: e["ErrorDetail"] for e in resp.get("Errors", [])}
    assert errors.get("9999", {}).get("ErrorCode") == "EntityNotFoundException", (
        f"unknown VersionId must yield EntityNotFoundException per entry, got {errors}"
    )
    assert errors["9999"].get("ErrorMessage") == "Version not found.", errors
    remaining = {
        v["VersionId"]
        for v in glue.get_table_versions(DatabaseName=db_name, TableName=tbl_name)["TableVersions"]
    }
    assert ids[1] not in remaining, "batch_delete_table_version did not remove the version"
    assert current_id in remaining, "current version must survive version pruning"

    batch_deleted_get_code, batch_deleted_get_message = _refusal(
        lambda: glue.get_table_version(DatabaseName=db_name, TableName=tbl_name, VersionId=ids[1])
    )
    assert batch_deleted_get_code == "EntityNotFoundException", (
        f"get_table_version on a version pruned by batch_delete_table_version must fail with "
        f"EntityNotFoundException, got {batch_deleted_get_code}"
    )
    assert batch_deleted_get_message == "Table version not found.", batch_deleted_get_message

    table = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert table["StorageDescriptor"]["Location"] == "s3://example-bucket/v4/", (
        f"current table location must remain the last-written v4, got "
        f"{table['StorageDescriptor']['Location']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
