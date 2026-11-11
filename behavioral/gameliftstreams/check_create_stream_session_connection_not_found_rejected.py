"""create-stream-session-connection-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-session-connection-not-found-rejected"
GROUP = "not-found"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamSessionConnection (the reconnect API) on a non-existent stream group /
    stream session pair is rejected with ResourceNotFoundException -- this identifier-lookup
    boundary doesn't require a real, billable stream group to exercise."""
    gls = ctx.client("gameliftstreams")
    bogus_group = ctx.unique_name("sg-")

    code, message = _error_code(
        lambda: gls.create_stream_session_connection(
            Identifier=bogus_group,
            StreamSessionIdentifier="ssdoesnotexist0",
            SignalRequest='{"type":"offer","sdp":"v=0"}',
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    session_arn = (
        f"arn:aws:gameliftstreams:{ctx.region}:{ctx.account}:streamsession/{bogus_group}/ssdoesnotexist0"
    )
    expected = f"Stream session '{session_arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected rejection, but create_stream_session_connection SUCCEEDED and returned {result!r}"
    )


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
