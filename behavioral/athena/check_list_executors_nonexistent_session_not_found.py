"""list-executors-nonexistent-session-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executors-nonexistent-session-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListExecutors rejects a session id that does not exist with InvalidRequestException and the
    exact message, not ResourceNotFoundException or an empty ExecutorsSummary list."""
    athena = ctx.client("athena")
    fake_session_id = str(uuid.uuid4())

    code, message = _error(lambda: athena.list_executors(SessionId=fake_session_id))
    assert code == "InvalidRequestException", f"ListExecutors: expected InvalidRequestException, got {code}"
    assert message == "Not authorized to make this request.", f"ListExecutors: unexpected message {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"ListExecutors: expected rejection of a nonexistent session, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
