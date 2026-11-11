"""table-batch-delete-partial-failure."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-batch-delete-partial-failure"
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


def _tolerate_not_found(call):
    """Teardown: a resource the check already deleted is not an error."""
    try:
        call()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """batch_delete_table deletes the existing tables and reports missing ones per-entry."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(
        DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    existing = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": existing,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "year", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: _tolerate_not_found(lambda: glue.delete_table(DatabaseName=db_name, Name=existing)))
    missing = ctx.unique_name("sim2real-behav-tbl-")

    resp = glue.batch_delete_table(DatabaseName=db_name, TablesToDelete=[existing, missing])

    errors = resp.get("Errors", [])
    error_names = {e["TableName"] for e in errors}
    assert error_names == {missing}, (
        f"expected only {missing} in Errors (the existing table must not be reported), got {errors}"
    )
    err = next(e for e in errors if e["TableName"] == missing)
    assert err["ErrorDetail"]["ErrorCode"] == "EntityNotFoundException", err
    assert err["ErrorDetail"]["ErrorMessage"] == f"Table {missing} not found", err

    # The existing table must genuinely be gone.
    code, message = _refusal(lambda: glue.get_table(DatabaseName=db_name, Name=existing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == "Entity Not Found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
