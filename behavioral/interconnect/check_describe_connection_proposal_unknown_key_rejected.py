"""describe-connection-proposal-unknown-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-connection-proposal-unknown-key-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeConnectionProposal with an activationKey unknown to the service (one that is not even
    valid base64) fails with InterconnectValidationException."""
    ic = ctx.client("interconnect")
    code, message = _error(
        lambda: ic.describe_connection_proposal(
            activationKey="sim2real-behav-unknown-activation-key-0000000000"
        )
    )
    assert code == "InterconnectValidationException", f"expected InterconnectValidationException, got {code!r}"
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
