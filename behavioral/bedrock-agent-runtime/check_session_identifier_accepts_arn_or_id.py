"""session-identifier-accepts-arn-or-id."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-identifier-accepts-arn-or-id"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSession accepts either the bare sessionId or the full sessionArn as sessionIdentifier."""
    client = ctx.client("bedrock-agent-runtime")
    created = client.create_session()
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    by_id = client.get_session(sessionIdentifier=session_id)
    by_arn = client.get_session(sessionIdentifier=session_arn)

    assert by_id["sessionId"] == by_arn["sessionId"] == session_id, (
        f"expected sessionId {session_id!r} from both lookups, "
        f"got by_id={by_id['sessionId']!r} by_arn={by_arn['sessionId']!r}"
    )
    assert by_id["sessionArn"] == by_arn["sessionArn"] == session_arn, (
        f"expected sessionArn {session_arn!r} from both lookups, "
        f"got by_id={by_id['sessionArn']!r} by_arn={by_arn['sessionArn']!r}"
    )
    assert by_id["sessionStatus"] == by_arn["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE from both lookups, "
        f"got by_id={by_id['sessionStatus']!r} by_arn={by_arn['sessionStatus']!r}"
    )


def _safe_end_and_delete(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
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
