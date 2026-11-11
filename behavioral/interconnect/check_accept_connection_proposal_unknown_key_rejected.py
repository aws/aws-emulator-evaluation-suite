"""accept-connection-proposal-unknown-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "accept-connection-proposal-unknown-key-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptConnectionProposal rejects an activationKey that was not issued via a real proposal (one
    that is not even valid base64) with InterconnectValidationException, on an account that otherwise
    has working access to the API."""
    ic = ctx.client("interconnect")

    # Positive control: prove this account/credentials are not just denied outright for the
    # service (accept-set below would otherwise also fire on a globally-denied caller).
    ic.list_connections()

    attach_point = {"directConnectGateway": "12345678-1234-1234-1234-123456789012"}
    code, message = _error(
        lambda: ic.accept_connection_proposal(
            attachPoint=attach_point,
            activationKey="sim2real-behav-unknown-activation-key-0000000000",
        )
    )
    assert code == "InterconnectValidationException", f"got {code!r}"
    expected = "Unable to process request: The provided activation key is not valid base64"
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
