"""session-endpoint-unknown-session-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-endpoint-unknown-session-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionEndpoint for a session id that was never created raises
    InvalidRequestException rather than an empty/successful response."""
    athena = ctx.client("athena")
    bogus_session_id = ctx.unique_name("sim2real-athena-nosession-")

    code, message = _error(lambda: athena.get_session_endpoint(SessionId=bogus_session_id))
    # Empirically (verified against real AWS) Athena rejects a well-formed but
    # unknown/never-created SessionId at request-validation time with
    # InvalidRequestException rather than surfacing a distinct not-found class.
    assert code == "InvalidRequestException", (
        f"expected an unknown SessionId to raise InvalidRequestException, got {code}"
    )
    assert message == "Not authorized to make this request.", (
        f"unexpected GetSessionEndpoint message for an unknown SessionId: {message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("real AWS rejects GetSessionEndpoint for an unknown SessionId, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
