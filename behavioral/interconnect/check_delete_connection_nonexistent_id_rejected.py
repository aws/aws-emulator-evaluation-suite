"""delete-connection-nonexistent-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-connection-nonexistent-id-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnection on a well-formed but nonexistent connection id returns ResourceNotFoundException."""
    ic = ctx.client("interconnect")
    connection_id = "lmcc-00000000"
    code, message = _error(lambda: ic.delete_connection(identifier=connection_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Unable to process request: Unable to retrieve connection {connection_id}, as it does not exist"
    assert message == expected, f"got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
