"""database-delete-cascades-to-tables."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "database-delete-cascades-to-tables"
GROUP = 'database'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """delete_database removes every table it contained (cascading delete)."""
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_database(Name=db_name)))
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
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name)))

    # Sanity: the table exists before the cascade.
    pre_name = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]["Name"]
    assert pre_name == tbl_name, f"expected table {tbl_name} to exist pre-cascade, got {pre_name}"

    glue.delete_database(Name=db_name)

    try:
        glue.get_database(Name=db_name)
        db_code, db_message = None, None
    except ClientError as exc:
        db_code = exc.response.get("Error", {}).get("Code")
        db_message = exc.response.get("Error", {}).get("Message")
    assert db_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {db_code}"
    expected = f"Database {db_name} not found."
    assert db_message == expected, f"expected message {expected!r}, got {db_message!r}"

    try:
        glue.get_table(DatabaseName=db_name, Name=tbl_name)
        tbl_code, tbl_message = None, None
    except ClientError as exc:
        tbl_code = exc.response.get("Error", {}).get("Code")
        tbl_message = exc.response.get("Error", {}).get("Message")
    assert tbl_code == "EntityNotFoundException", (
        f"table survived the database delete or reported {tbl_code}"
    )
    assert tbl_message == "Entity Not Found", f"unexpected not-found message {tbl_message!r}"


def _ignore_not_found(fn):
    """Teardown: the check deletes the database itself, so not-found here is success."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
