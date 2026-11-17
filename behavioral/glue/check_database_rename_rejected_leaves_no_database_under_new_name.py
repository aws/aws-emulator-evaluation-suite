"""database-rename-rejected-leaves-no-database-under-new-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "database-rename-rejected-leaves-no-database-under-new-name"
GROUP = "database"
SERVICES = ["glue"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A same-name UpdateDatabase's Description and LocationUri round-trip through GetDatabase.
    One that also changes DatabaseInput.Name raises InvalidInputException ("Database cannot be
    renamed"), leaves the original untouched, and GetDatabase on the new name raises EntityNotFoundException."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-db-")
    initial_location = f"s3://example-bucket/{name}/initial/"
    glue.create_database(
        DatabaseInput={"Name": name, "Description": "initial description", "LocationUri": initial_location}
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=name), "EntityNotFoundException"))

    created = glue.get_database(Name=name)["Database"]
    assert created["Description"] == "initial description", (
        f"expected initial description, got {created.get('Description')!r}"
    )
    assert created["LocationUri"] == initial_location, (
        f"expected {initial_location!r}, got {created.get('LocationUri')!r}"
    )

    # Same-name update: Description and LocationUri both change and both round-trip exactly.
    updated_location = f"s3://example-bucket/{name}/updated/"
    glue.update_database(
        Name=name,
        DatabaseInput={"Name": name, "Description": "updated description", "LocationUri": updated_location},
    )
    updated = glue.get_database(Name=name)["Database"]
    assert updated["Description"] == "updated description", (
        f"expected updated description, got {updated.get('Description')!r}"
    )
    assert updated["LocationUri"] == updated_location, (
        f"expected {updated_location!r}, got {updated.get('LocationUri')!r}"
    )

    new_name = name + "-renamed"
    # Registered before the rename attempt: if AWS ever accepted it, the database minted under
    # new_name must still be torn down.
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=new_name), "EntityNotFoundException"))

    _RENAME_REJECTED = ("InvalidInputException", "Database cannot be renamed")
    expect_error(
        lambda: glue.update_database(
            Name=name,
            DatabaseInput={"Name": new_name, "Description": "renamed description", "LocationUri": updated_location},
        ),
        *_RENAME_REJECTED,
        undo=lambda _result: glue.delete_database(Name=new_name),
    )

    # The database under the original name is unchanged by the rejected call: it still carries
    # the values from the preceding same-name update, not the renamed call's Description.
    after = glue.get_database(Name=name)["Database"]
    assert after["Description"] == "updated description", (
        f"rejected rename must not partially apply: expected updated description, got {after.get('Description')!r}"
    )
    assert after["LocationUri"] == updated_location, (
        f"rejected rename must not partially apply: expected {updated_location!r}, got {after.get('LocationUri')!r}"
    )

    # No database exists under the name the rejected rename would have created.
    _NEW_NAME_ABSENT = ("EntityNotFoundException", f"Database {new_name} not found.")
    expect_error(lambda: glue.get_database(Name=new_name), *_NEW_NAME_ABSENT)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
