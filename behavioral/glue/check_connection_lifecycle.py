"""connection-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-lifecycle"
GROUP = 'connection'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Connection create -> get -> update -> delete, with GetConnections reflecting each step,
    and the dead name both unusable and reusable once torn down."""
    glue = ctx.client("glue")
    conn_name = ctx.unique_name("sim2real-behav-glue-conn-")

    def _connection_input(url: str) -> dict:
        return {
            "Name": conn_name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": url,
                "USERNAME": "admin",
                "PASSWORD": "placeholder-not-a-real-secret",
            },
        }

    glue.create_connection(
        ConnectionInput=_connection_input("jdbc:mysql://db1.example.com:3306/mydb"),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_connection(ConnectionName=conn_name)))

    conn = glue.get_connection(Name=conn_name)["Connection"]
    assert conn["ConnectionType"] == "JDBC", f"unexpected ConnectionType: {conn}"
    assert conn["ConnectionProperties"]["JDBC_CONNECTION_URL"] == "jdbc:mysql://db1.example.com:3306/mydb", (
        f"expected the just-created JDBC URL, got {conn['ConnectionProperties'].get('JDBC_CONNECTION_URL')!r}"
    )

    glue.update_connection(
        Name=conn_name,
        ConnectionInput=_connection_input("jdbc:mysql://db2.example.com:3306/mydb"),
    )
    updated = glue.get_connection(Name=conn_name)["Connection"]
    assert (
        updated["ConnectionProperties"]["JDBC_CONNECTION_URL"]
        == "jdbc:mysql://db2.example.com:3306/mydb"
    ), "UpdateConnection did not persist the new JDBC URL"

    names = [c["Name"] for c in glue.get_connections()["ConnectionList"]]
    assert conn_name in names, "connection missing from GetConnections listing"

    glue.delete_connection(ConnectionName=conn_name)
    code, msg = _error(lambda: glue.get_connection(Name=conn_name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteConnection, got {code!r}"
    )
    assert msg == f"Connection with name {conn_name} in account {ctx.account} is not found", (
        f"unexpected GetConnection message: {msg!r}"
    )

    update_code, update_msg = _error(
        lambda: glue.update_connection(
            Name=conn_name,
            ConnectionInput=_connection_input("jdbc:mysql://db3.example.com:3306/mydb"),
        )
    )
    assert update_code == "EntityNotFoundException", (
        f"UpdateConnection on a deleted connection must fail with EntityNotFoundException, got {update_code!r}"
    )
    assert update_msg == f"Connection not found: {conn_name}", f"unexpected UpdateConnection message: {update_msg!r}"

    names_after_delete = [c["Name"] for c in glue.get_connections()["ConnectionList"]]
    assert conn_name not in names_after_delete, "deleted connection still present in GetConnections listing"

    glue.create_connection(ConnectionInput=_connection_input("jdbc:mysql://db4.example.com:3306/mydb"))
    recreated = glue.get_connection(Name=conn_name)["Connection"]
    assert recreated["ConnectionProperties"]["JDBC_CONNECTION_URL"] == "jdbc:mysql://db4.example.com:3306/mydb", (
        "deleted connection name must be reusable by a fresh CreateConnection"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _quiet(fn):
    """Best-effort teardown call — the resource may already be gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
