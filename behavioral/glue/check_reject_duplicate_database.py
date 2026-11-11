"""reject-duplicate-database."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-duplicate-database"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDatabase on an existing name raises AlreadyExistsException ("Database already exists.")
    and keeps the original Description; another name is created, and after deletion the name can
    be created again.
    """
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": name, "Description": "original-description"}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_ignore_missing(glue, name))

    code, message = _error(
        lambda: glue.create_database(DatabaseInput={"Name": name, "Description": "clobbered-description"})
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}"
    assert message == "Database already exists.", f"unexpected AlreadyExistsException message {message!r}"

    # Effect absent: the rejected call did not overwrite the original database's properties.
    fetched = glue.get_database(Name=name)["Database"]
    assert fetched["Description"] == "original-description", (
        f"expected original-description, got {fetched['Description']!r}"
    )

    # Positive control: a genuinely different name still creates successfully.
    other_name = ctx.unique_name("sim2real-behav-db-other-")
    glue.create_database(DatabaseInput={"Name": other_name, "Description": "second-database"}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_ignore_missing(glue, other_name))
    other_desc = glue.get_database(Name=other_name)["Database"]["Description"]
    assert other_desc == "second-database", f"expected second-database, got {other_desc!r}"

    # Restore: delete the original, confirm it's gone via an independent read, then the identical
    # create call (same name) now succeeds -- the identifier is reusable, not permanently reserved.
    glue.delete_database(Name=name)
    gone_code, gone_message = _error(lambda: glue.get_database(Name=name))
    assert gone_code == "EntityNotFoundException", f"expected EntityNotFoundException, got {gone_code}"
    expected = f"Database {name} not found."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    glue.create_database(DatabaseInput={"Name": name, "Description": "recreated-description"}, Tags={"sim2real": CHECK})
    recreated = glue.get_database(Name=name)["Database"]
    assert recreated["Description"] == "recreated-description", (
        f"expected recreated-description, got {recreated['Description']!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_ignore_missing(glue, name: str) -> None:
    try:
        glue.delete_database(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
