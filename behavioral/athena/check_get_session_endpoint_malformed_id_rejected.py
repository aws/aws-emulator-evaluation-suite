"""get-session-endpoint-malformed-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-session-endpoint-malformed-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionEndpoint rejects a malformed session id with InvalidRequestException and the exact
    pattern-validation message instead of returning an endpoint for it."""
    athena = ctx.client("athena")

    malformed_id = "!! not-a-session-id ??"
    malformed_code, malformed_message = _error(
        lambda: athena.get_session_endpoint(SessionId=malformed_id)
    )
    assert malformed_code == "InvalidRequestException", (
        f"expected a malformed SessionId to raise InvalidRequestException, "
        f"got {malformed_code!r}"
    )
    assert malformed_message == (
        "1 validation error detected: Value at 'sessionId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^[0-9a-z-_]+$"
    ), f"unexpected GetSessionEndpoint message: {malformed_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

