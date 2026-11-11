"""get-session-accessors-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-accessors-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSession, GetSessionStatus, GetSessionEndpoint and TerminateSession all fail
    InvalidRequestException, and only that, for a well-formed SessionId never created."""
    athena = ctx.client("athena")
    # A syntactically valid (but never-issued) UUID is still rejected by the real service as
    # InvalidRequestException.
    bogus_session_id = str(uuid.uuid4())

    cases = {
        "GetSession": lambda: athena.get_session(SessionId=bogus_session_id),
        "GetSessionStatus": lambda: athena.get_session_status(SessionId=bogus_session_id),
        "GetSessionEndpoint": lambda: athena.get_session_endpoint(SessionId=bogus_session_id),
        "TerminateSession": lambda: athena.terminate_session(SessionId=bogus_session_id),
    }
    actual = {label: _error_code(label, fn) for label, fn in cases.items()}
    deviations = {label: code for label, code in actual.items() if code != "InvalidRequestException"}
    assert not deviations, (
        f"expected InvalidRequestException from every accessor on a never-issued SessionId; "
        f"deviations: {deviations}"
    )


def _error_code(label, fn):
    """Call fn() and return its ClientError code; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"{label} unexpectedly succeeded against a never-issued SessionId and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
