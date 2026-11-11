"""get-session-endpoint-status-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-session-endpoint-status-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSession, GetSessionStatus and GetSessionEndpoint each reject a session id that was never
    created with InvalidRequestException and the exact message, not ResourceNotFoundException."""
    athena = ctx.client("athena")
    fake_session_id = str(uuid.uuid4())

    code, message = _error(lambda: athena.get_session(SessionId=fake_session_id))
    assert code == "InvalidRequestException", f"GetSession: expected InvalidRequestException, got {code}"
    assert message == "Not authorized to make this request.", f"GetSession: unexpected message {message!r}"

    code, message = _error(lambda: athena.get_session_status(SessionId=fake_session_id))
    assert code == "InvalidRequestException", f"GetSessionStatus: expected InvalidRequestException, got {code}"
    assert message == "Not authorized to make this request.", (
        f"GetSessionStatus: unexpected message {message!r}"
    )

    code, message = _error(lambda: athena.get_session_endpoint(SessionId=fake_session_id))
    assert code == "InvalidRequestException", f"GetSessionEndpoint: expected InvalidRequestException, got {code}"
    assert message == "Not authorized to make this request.", (
        f"GetSessionEndpoint: unexpected message {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
