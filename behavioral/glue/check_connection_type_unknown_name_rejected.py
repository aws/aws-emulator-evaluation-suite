"""connection-type-unknown-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-type-unknown-name-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeConnectionType on a connector type name nobody registered fails
    InvalidInputException, while DeleteConnectionType on that same name, and on a built-in
    connector type AWS publishes in every account, both fail EntityNotFoundException instead.
    """
    glue = ctx.client("glue")

    missing = ctx.unique_name("sim2real-behav-conntype-missing-")
    code, message = _error(lambda: glue.describe_connection_type(ConnectionType=missing))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}: {message!r}"
    assert message == "The connection type is not available.", (
        f"unexpected message for an unknown connection type: {message!r}"
    )

    # Positive control: the identical shape of call against a built-in connector type succeeds.
    builtin = "ADOBEANALYTICS"
    described = glue.describe_connection_type(ConnectionType=builtin)
    assert described["ConnectionType"] == builtin, (
        f"expected DescribeConnectionType to echo back {builtin!r}, got {described.get('ConnectionType')!r}"
    )

    code, message = _error(lambda: glue.delete_connection_type(ConnectionType=missing))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == f"Connection type {missing} does not exist", (
        f"unexpected message for DeleteConnectionType on an unknown name: {message!r}"
    )

    # A built-in connector type is not a custom registration this account holds: DeleteConnectionType
    # refuses it the same way it refuses a name nobody ever registered.
    code, message = _error(lambda: glue.delete_connection_type(ConnectionType=builtin))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}: {message!r}"
    assert message == f"Connection type {builtin} does not exist", (
        f"unexpected message for DeleteConnectionType on a built-in type: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
