"""database-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "database-create-get-delete"
GROUP = 'database'
SERVICES = ['glue']


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_database_if_present(glue, name):
    """Teardown: delete the database, tolerating one the check already deleted."""
    try:
        glue.delete_database(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_database -> get_database reflects input -> delete_database removes it,
    blocks further mutation, and frees the name for reuse."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-db-")
    desc = "behavioral fidelity check database"
    glue.create_database(DatabaseInput={"Name": name, "Description": desc})
    ctx.on_cleanup(lambda: _delete_database_if_present(glue, name))

    resp = glue.get_database(Name=name)
    assert resp["Database"]["Name"] == name, f"expected database name {name}, got {resp['Database']['Name']!r}"
    assert resp["Database"]["Description"] == desc, (
        f"expected description {desc!r}, got {resp['Database']['Description']!r}"
    )

    glue.delete_database(Name=name)

    code, status, message = _error(lambda: glue.get_database(Name=name))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx on GetDatabase of the deleted database, got {status}"
    expected_message = f"Database {name} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # The paginated catalog listing no longer contains the name.
    listed = [
        d["Name"] for page in glue.get_paginator("get_databases").paginate() for d in page["DatabaseList"]
    ]
    assert name not in listed, "the deleted database is still listed by GetDatabases"

    # A mutation on the dead id must also fail, not just a read.
    update_code, update_status, update_message = _error(
        lambda: glue.update_database(Name=name, DatabaseInput={"Name": name, "Description": "post-delete update"})
    )
    assert update_code == "EntityNotFoundException", (
        f"expected update_database on a deleted database to fail with EntityNotFoundException, "
        f"got {update_code}"
    )
    assert isinstance(update_status, int) and 400 <= update_status < 500, f"expected HTTP 4xx on UpdateDatabase of the deleted database, got {update_status}"
    expected_message = f"Database {name} not found."
    assert update_message == expected_message, f"expected the message {expected_message!r}, got {update_message!r}"

    # The freed name must be reusable immediately.
    recreated_desc = "recreated after delete"
    glue.create_database(DatabaseInput={"Name": name, "Description": recreated_desc})
    ctx.on_cleanup(lambda: _delete_database_if_present(glue, name))
    resp = glue.get_database(Name=name)
    assert resp["Database"]["Description"] == recreated_desc, (
        f"expected the freed name {name} to be reusable with a fresh description, "
        f"got {resp['Database']['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
