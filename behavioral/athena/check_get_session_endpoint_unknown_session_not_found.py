"""get-session-endpoint-unknown-session-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-session-endpoint-unknown-session-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSession on a missing workgroup and GetSessionEndpoint for a session id that was never
    created both raise InvalidRequestException with their exact messages, never a fabricated endpoint."""
    athena = ctx.client("athena")

    # Exercise StartSession first: a bogus/nonexistent WorkGroup can never produce a
    # real session, so any SessionId we probe afterwards is guaranteed unassociated
    # with anything StartSession created.
    bogus_wg = ctx.unique_name("sim2real-behav-nowg-")
    start_code, start_message = _error(
        lambda: athena.start_session(WorkGroup=bogus_wg, EngineConfiguration={})
    )
    assert start_code == "InvalidRequestException", f"GOT={start_code!r}"
    assert start_message == "WorkGroup is not found.", f"GOT message={start_message!r}"

    bogus_session_id = str(uuid.uuid4())
    code, message = _error(lambda: athena.get_session_endpoint(SessionId=bogus_session_id))
    assert code == "InvalidRequestException", f"GOT={code!r}"
    assert message == "Not authorized to make this request.", f"GOT message={message!r}"


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

