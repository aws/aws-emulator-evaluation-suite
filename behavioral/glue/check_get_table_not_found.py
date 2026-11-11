"""get-table-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-not-found"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """get_table on an unknown database, and on an unknown table within a real database,
    raises EntityNotFoundException specifically — proven against a real table so a target
    that raises EntityNotFoundException unconditionally cannot pass."""
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
                "Columns": [{"Name": "id", "Type": "int"}],
                "Location": "s3://example-bucket/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    # Positive control: get_table on the real table succeeds.
    resp = glue.get_table(DatabaseName=db_name, Name=tbl_name)
    assert resp["Table"]["Name"] == tbl_name, resp["Table"]

    missing_db = ctx.unique_name("sim2real-behav-db-missing-")
    try:
        glue.get_table(DatabaseName=missing_db, Name="does-not-exist")
    except ClientError as exc:
        db_code = exc.response["Error"]["Code"]
        db_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError("get_table on a missing entity succeeded; it must be refused")
    assert db_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for a missing database, got {db_code}"
    )
    expected = 'Entity Not Found'
    assert db_message == expected, f"expected message {expected!r}, got {db_message!r}"

    try:
        glue.get_table(DatabaseName=db_name, Name="does-not-exist")
    except ClientError as exc:
        tbl_code = exc.response["Error"]["Code"]
        tbl_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError("get_table on a missing entity succeeded; it must be refused")
    assert tbl_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for a missing table, got {tbl_code}"
    )
    expected = 'Entity Not Found'
    assert tbl_message == expected, f"expected message {expected!r}, got {tbl_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
