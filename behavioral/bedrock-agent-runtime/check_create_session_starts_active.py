"""create-session-starts-active."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-session-starts-active"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession's createdAt reflects the real creation instant (within a generous
    clock-skew tolerance of "now"), not a stale, default, or zero timestamp; GetSession
    echoes back the identical createdAt afterward."""
    client = ctx.client("bedrock-agent-runtime")

    before = datetime.datetime.now(datetime.timezone.utc)
    created = client.create_session()
    after = datetime.datetime.now(datetime.timezone.utc)
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    assert created["sessionStatus"] == "ACTIVE", (
        f"expected sessionStatus ACTIVE, got {created['sessionStatus']!r}"
    )

    created_at = created["createdAt"]
    assert isinstance(created_at, datetime.datetime), (
        f"expected createdAt to be a datetime, got {type(created_at).__name__}: {created_at!r}"
    )
    tolerance = datetime.timedelta(minutes=5)
    assert before - tolerance <= created_at <= after + tolerance, (
        f"createdAt {created_at} is not close to the actual creation window "
        f"[{before}, {after}]"
    )

    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["createdAt"] == created_at, (
        f"GetSession createdAt {fetched['createdAt']} != CreateSession createdAt {created_at}"
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
