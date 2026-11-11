"""list-sessions-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-sessions-invalid-next-token-rejected"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSessions with a nextToken the service never issued gets ValidationException "Next token for
    pagination is invalid", while the same call without a token lists the check's session."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session(tags={"simparity-check": CHECK})["sessionId"]

    def _end_and_delete() -> None:
        client.end_session(sessionIdentifier=session_id)
        client.delete_session(sessionIdentifier=session_id)

    ctx.on_cleanup(_end_and_delete)

    bogus_token = "not-a-real-pagination-token-" + "z" * 40
    code, message = _error(lambda: client.list_sessions(nextToken=bogus_token))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Next token for pagination is invalid", (
        f"expected message 'Next token for pagination is invalid', got {message!r}"
    )

    # Positive control: the same account, same session, no token -> succeeds.
    listed_ids = set()
    next_token = None
    for _ in range(500):
        kwargs = {"maxResults": 20}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_sessions(**kwargs)
        listed_ids.update(s["sessionId"] for s in resp.get("sessionSummaries", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    assert session_id in listed_ids, "positive control: our session must still be listable"


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
