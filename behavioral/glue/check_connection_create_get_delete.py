"""connection-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-create-get-delete"
GROUP = 'connection'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_connection -> get_connection reflects type/properties -> delete_connection removes it."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-conn-")

    glue.create_connection(
        ConnectionInput={
            "Name": name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/db",
                "USERNAME": "admin",
                "PASSWORD": "super-secret-password",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_connection_ignoring_not_found(glue, name))

    resp = glue.get_connection(Name=name)
    conn = resp["Connection"]
    assert conn["Name"] == name, f"expected connection name {name!r}, got {conn['Name']!r}"
    assert conn["ConnectionType"] == "JDBC", (
        f"expected ConnectionType JDBC, got {conn['ConnectionType']!r}"
    )

    glue.delete_connection(ConnectionName=name)

    get_code, get_msg = _error(lambda: glue.get_connection(Name=name))
    assert get_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from get_connection after delete, got {get_code!r}"
    )
    assert get_msg == f"Connection with name {name} in account {ctx.account} is not found", (
        f"unexpected get_connection message: {get_msg!r}"
    )

    delete_code, delete_msg = _error(lambda: glue.delete_connection(ConnectionName=name))
    assert delete_code == "EntityNotFoundException", (
        "expected EntityNotFoundException from delete_connection on an already-deleted "
        f"connection, got {delete_code!r}"
    )
    assert delete_msg == "Connection not found", f"unexpected delete_connection message: {delete_msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")



def _delete_connection_ignoring_not_found(glue, name):
    try:
        glue.delete_connection(ConnectionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
