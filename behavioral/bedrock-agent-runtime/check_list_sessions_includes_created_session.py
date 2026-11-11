"""list-sessions-includes-created-session."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-sessions-includes-created-session"
GROUP = "listing"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created session shows up in ListSessions, paging through if necessary,
    and is gone from it once ended and deleted."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

    def _cleanup():
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            client.delete_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    def _list_has(target_id):
        next_token = None
        pages = 0
        while True:
            kwargs = {"maxResults": 100}
            if next_token:
                kwargs["nextToken"] = next_token
            page = client.list_sessions(**kwargs)
            pages += 1
            if any(s["sessionId"] == target_id for s in page["sessionSummaries"]):
                return True, pages
            next_token = page.get("nextToken")
            if not next_token or pages > 50:
                return False, pages

    found, pages = _list_has(session_id)
    assert found, f"session {session_id} was not found in ListSessions after {pages} page(s)"

    client.end_session(sessionIdentifier=session_id)
    client.delete_session(sessionIdentifier=session_id)

    found_after_delete, pages_after = _list_has(session_id)
    assert not found_after_delete, (
        f"session {session_id} still appeared in ListSessions after {pages_after} page(s) "
        "following EndSession+DeleteSession"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
