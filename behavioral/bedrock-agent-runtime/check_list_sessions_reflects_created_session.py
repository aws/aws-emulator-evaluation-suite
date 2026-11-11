"""list-sessions-reflects-created-session."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-sessions-reflects-created-session"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created session shows up in ListSessions with the correct status, and
    disappears from it once deleted."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    found = _find_session(client, session_id)
    assert found is not None, f"session {session_id} not found in ListSessions after CreateSession"
    assert found["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE in ListSessions for {session_id}, got {found['sessionStatus']!r}"
    )

    client.end_session(sessionIdentifier=session_id)
    client.delete_session(sessionIdentifier=session_id)

    found_after_delete = _find_session(client, session_id)
    assert found_after_delete is None, (
        f"session {session_id} still present in ListSessions after DeleteSession: {found_after_delete!r}"
    )


def _find_session(client, session_id: str):
    next_token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_sessions(**kwargs)
        pages += 1
        for summary in resp.get("sessionSummaries", []):
            if summary["sessionId"] == session_id:
                return summary
        next_token = resp.get("nextToken")
        if not next_token or pages > 50:
            return None


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
