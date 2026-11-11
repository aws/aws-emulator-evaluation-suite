"""session-lifecycle-active-ended-deleted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-lifecycle-active-ended-deleted"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession starts ACTIVE; EndSession transitions to ENDED; DeleteSession then removes
    it so a mutation on the dead id (EndSession again) and GetSession both raise the same specific
    ResourceNotFoundException rather than silently no-op'ing."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    assert created["sessionStatus"] == "ACTIVE", (
        f"expected CreateSession to start ACTIVE, got {created['sessionStatus']!r}"
    )

    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    got = client.get_session(sessionIdentifier=session_id)
    assert got["sessionStatus"] == "ACTIVE", (
        f"expected GetSession to report ACTIVE right after create, got {got['sessionStatus']!r}"
    )

    ended = client.end_session(sessionIdentifier=session_id)
    assert ended["sessionStatus"] == "ENDED", (
        f"expected EndSession to transition to ENDED, got {ended['sessionStatus']!r}"
    )
    assert ended["sessionId"] == session_id, (
        f"expected EndSession to echo session id {session_id!r}, got {ended['sessionId']!r}"
    )

    got2 = client.get_session(sessionIdentifier=session_id)
    assert got2["sessionStatus"] == "ENDED", (
        f"expected GetSession to report ENDED after EndSession, got {got2['sessionStatus']!r}"
    )

    client.delete_session(sessionIdentifier=session_id)

    expected_message = f"Session with ID {session_id} not found"
    end_code, end_message = _error(lambda: client.end_session(sessionIdentifier=session_id))
    assert end_code == "ResourceNotFoundException", (
        "expected EndSession on the deleted session id to also raise "
        f"ResourceNotFoundException, got {end_code!r}"
    )
    assert end_message == expected_message, (
        f"expected EndSession message {expected_message!r}, got {end_message!r}"
    )

    code, message = _error(lambda: client.get_session(sessionIdentifier=session_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetSession on a deleted session to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == expected_message, (
        f"expected GetSession message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
