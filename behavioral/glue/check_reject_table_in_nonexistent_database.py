"""reject-table-in-nonexistent-database."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-table-in-nonexistent-database"
GROUP = 'overly-permissive'
SERVICES = ['glue']


def _refusal(call):
    """(code, HTTP status, message) of a call that MUST fail — raises on unexpected success rather
    than returning a falsy sentinel."""
    try:
        call()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_table against a database that does not exist yet must fail, and must start
    succeeding the moment that same database is created — proving the refusal tracks the
    database's existence rather than a target that rejects every CreateTable call outright."""
    glue = ctx.client("glue")
    missing_db = ctx.unique_name("sim2real-behav-no-such-db-")
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    table_input = {
        "Name": tbl_name,
        "StorageDescriptor": {"Columns": [{"Name": "id", "Type": "int"}]},
    }

    # ---- positive control: the identical shape of call succeeds against a real database ----
    control_db = ctx.unique_name("sim2real-behav-control-db-")
    glue.create_database(DatabaseInput={"Name": control_db}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=control_db))
    control_tbl = ctx.unique_name("sim2real-behav-control-tbl-")
    glue.create_table(DatabaseName=control_db, TableInput={**table_input, "Name": control_tbl})
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=control_db, Name=control_tbl))
    control_got = glue.get_table(DatabaseName=control_db, Name=control_tbl)["Table"]
    assert control_got["Name"] == control_tbl, (
        f"the positive control table did not round-trip: {control_got!r} — CreateTable itself "
        f"is broken, not merely the missing-database case"
    )

    # ---- break exactly one thing: DatabaseName that was never created ----
    code, status, message = _refusal(
        lambda: glue.create_table(DatabaseName=missing_db, TableInput=table_input)
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert status == 400, f"expected HTTP 400 for CreateTable in a missing database, got {status}"
    expected_message = f"Database {missing_db} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # ---- effect absent: an independent read confirms nothing was created ----
    code, status, message = _refusal(lambda: glue.get_table(DatabaseName=missing_db, Name=tbl_name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException reading back the table whose creation was refused, "
        f"got {code}"
    )
    assert status == 400, f"expected HTTP 400 reading back the refused table, got {status}"
    expected_message = "Entity Not Found"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # ---- restore: create the missing database ----
    glue.create_database(DatabaseInput={"Name": missing_db}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=missing_db))

    # ---- the IDENTICAL create_table call now succeeds ----
    glue.create_table(DatabaseName=missing_db, TableInput=table_input)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=missing_db, Name=tbl_name))
    created = glue.get_table(DatabaseName=missing_db, Name=tbl_name)["Table"]
    assert created["Name"] == tbl_name, (
        f"CreateTable succeeded once the database existed, but GetTable does not see it: {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
