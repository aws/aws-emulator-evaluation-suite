"""create-database-duplicate-name-rejected."""
from __future__ import annotations

import botocore

from behavioral_harness import tags

CHECK = "create-database-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDatabase with a Name in use fails with AlreadyExistsException 'Database already exists.' and
    keeps the original Description; another name creates, and the name is reusable once the original is
    deleted.
    """
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-db-dup-")
    glue.create_database(DatabaseInput={"Name": name, "Description": "original-description"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))

    code, message = _error(
        lambda: glue.create_database(DatabaseInput={"Name": name, "Description": "clobbered-description"})
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    assert message == "Database already exists.", f"unexpected CreateDatabase message: {message!r}"

    # Effect absent: the original database's description was not overwritten by the rejected call.
    fetched = glue.get_database(Name=name)["Database"]
    assert fetched["Description"] == "original-description", (
        f"expected original-description preserved, got {fetched['Description']!r}"
    )

    # Positive control: creating a database under a genuinely different name still succeeds.
    other_name = ctx.unique_name("sim2real-db-dup2-")
    glue.create_database(DatabaseInput={"Name": other_name, "Description": "second-database"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=other_name))
    other_desc = glue.get_database(Name=other_name)["Database"]["Description"]
    assert other_desc == "second-database", f"expected second-database, got {other_desc!r}"

    # Restore: free the name by deleting the original database; an independent read shows it gone, and the
    # identical create call then succeeds, so the rejection was tied to the name being taken.
    glue.delete_database(Name=name)
    gone_code, gone_message = _error(lambda: glue.get_database(Name=name))
    assert gone_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {gone_code!r}"
    assert gone_message == f"Database {name} not found.", f"unexpected GetDatabase message: {gone_message!r}"

    glue.create_database(DatabaseInput={"Name": name, "Description": "recreated-after-delete"})
    recreated_desc = glue.get_database(Name=name)["Database"]["Description"]
    assert recreated_desc == "recreated-after-delete", (
        f"expected recreated-after-delete, got {recreated_desc!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
