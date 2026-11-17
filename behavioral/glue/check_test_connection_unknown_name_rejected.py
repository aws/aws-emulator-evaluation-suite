"""test-connection-unknown-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-connection-unknown-name-rejected"
GROUP = "connection"
SERVICES = ["glue"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_connection_ignoring_not_found(glue, name):
    try:
        glue.delete_connection(ConnectionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestConnection on a connection name nobody created fails EntityNotFoundException with the
    name quoted, while the identical call against a real stored connection reaches a distinct,
    later validation instead — proving the refusal keys on existence, not on the name's shape.
    """
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

    missing = ctx.unique_name("sim2real-behav-conn-missing-")
    code, message = _error(lambda: glue.test_connection(ConnectionName=missing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    expected_missing = f"Connection with name {missing} in account {ctx.account} is not found"
    assert message == expected_missing, f"unexpected message for a missing connection: {message!r}"

    # Positive control: the identical call against a connection that really exists gets past
    # the not-found check and is refused for an unrelated, later reason instead.
    code, message = _error(lambda: glue.test_connection(ConnectionName=name))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "This operation is only supported for the Unified Connections", (
        f"unexpected ValidationException message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
