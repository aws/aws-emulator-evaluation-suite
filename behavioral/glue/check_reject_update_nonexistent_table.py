"""reject-update-nonexistent-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-update-nonexistent-table"
GROUP = 'overly-permissive'
SERVICES = ['glue']


def _table_input(name: str, col_type: str) -> dict:
    return {"Name": name, "StorageDescriptor": {"Columns": [{"Name": "c", "Type": col_type}]}}


def _col_type(table: dict) -> str:
    return table["StorageDescriptor"]["Columns"][0]["Type"]


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable on a deleted table raises EntityNotFoundException ("Table <name> not found.")
    without recreating it (GetTable: "Entity Not Found"); the same update succeeds before
    deletion and after re-creation.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")

    # Positive control: UpdateTable on a table that DOES exist succeeds.
    glue.create_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, "string"))
    glue.update_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, "int"))
    control = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert _col_type(control) == "int", (
        f"positive control: UpdateTable did not apply, GetTable shows {_col_type(control)!r}"
    )

    # The one broken thing: the table no longer exists.
    glue.delete_table(DatabaseName=db_name, Name=tbl_name)

    code, message = _error(
        lambda: glue.update_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, "float"))
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == f"Table {tbl_name} not found.", message

    # And it must NOT have been created as a side effect.
    get_code, get_message = _error(lambda: glue.get_table(DatabaseName=db_name, Name=tbl_name))
    assert get_code == "EntityNotFoundException", (
        f"update_table upserted a new table (get returned {get_code})"
    )
    assert get_message == "Entity Not Found", get_message

    # Restore, then the IDENTICAL call must now succeed.
    glue.create_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, "string"))
    glue.update_table(DatabaseName=db_name, TableInput=_table_input(tbl_name, "float"))
    restored = glue.get_table(DatabaseName=db_name, Name=tbl_name)["Table"]
    assert _col_type(restored) == "float", (
        f"after restoring the table, the identical UpdateTable call that was rejected did "
        f"not apply once the table existed again; GetTable shows {_col_type(restored)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
