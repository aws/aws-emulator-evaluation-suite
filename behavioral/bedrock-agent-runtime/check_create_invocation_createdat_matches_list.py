"""create-invocation-createdat-matches-list."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-createdat-matches-list"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new invocation is listed once by ListInvocations with its sessionId and a createdAt within the
    wall-clock window of the call, and a second read returns the same createdAt."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "sim2real"})["sessionId"]

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

    before = dt.datetime.now(dt.timezone.utc)
    created = client.create_invocation(sessionIdentifier=session_id)
    after = dt.datetime.now(dt.timezone.utc)
    invocation_id = created["invocationId"]

    listed = client.list_invocations(sessionIdentifier=session_id)
    matches = [s for s in listed["invocationSummaries"] if s["invocationId"] == invocation_id]
    assert len(matches) == 1, (
        f"expected exactly 1 ListInvocations summary for {invocation_id}, got {len(matches)}"
    )
    summary = matches[0]

    created_at = summary["createdAt"]
    assert isinstance(created_at, dt.datetime), (
        f"expected createdAt to be a real timestamp, got {type(created_at)!r}: {created_at!r}"
    )
    slack = dt.timedelta(seconds=5)
    assert before - slack <= created_at <= after + slack, (
        f"expected createdAt in [{before - slack}, {after + slack}] "
        f"(CreateInvocation call window +-5s skew), got {created_at}"
    )
    assert summary["sessionId"] == session_id, (
        f"expected sessionId {session_id!r}, got {summary['sessionId']!r}"
    )

    listed_again = client.list_invocations(sessionIdentifier=session_id)
    matches_again = [
        s for s in listed_again["invocationSummaries"] if s["invocationId"] == invocation_id
    ]
    assert len(matches_again) == 1, (
        f"expected the invocation to still be listed on a second independent read, "
        f"got {len(matches_again)} matches"
    )
    assert matches_again[0]["createdAt"] == created_at, (
        f"expected createdAt to be stable across independent reads, "
        f"got {created_at} then {matches_again[0]['createdAt']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
