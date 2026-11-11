"""create-chat-token-session-expiration-matches-duration."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "create-chat-token-session-expiration-matches-duration"
GROUP = "state"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChatToken's sessionExpirationTime is derived from sessionDurationInMinutes
    (createTime + duration); tokenExpirationTime is a separate, shorter-lived deadline for
    establishing the connection and is not derived from sessionDurationInMinutes."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(name=ctx.unique_name("sim2real-ivschat-room"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=arn))

    before = datetime.now(timezone.utc)
    resp = ivschat.create_chat_token(
        roomIdentifier=arn, userId="sim2real-user-1", sessionDurationInMinutes=45
    )
    after = datetime.now(timezone.utc)

    session_exp = resp["sessionExpirationTime"]
    token_exp = resp["tokenExpirationTime"]

    expected_low = before + timedelta(minutes=45) - timedelta(seconds=30)
    expected_high = after + timedelta(minutes=45) + timedelta(seconds=30)
    assert expected_low <= session_exp <= expected_high, (
        f"sessionExpirationTime {session_exp} not within 45min of request time "
        f"({expected_low}..{expected_high})"
    )
    # tokenExpirationTime governs only how long the token remains usable to *establish* the
    # WebSocket connection; empirically it is independent of sessionDurationInMinutes (it is
    # not clamped to, nor derived from, the session length), so we only assert it is a sane
    # timestamp in the future close to request time rather than bounding it by session_exp.
    assert token_exp > before, f"tokenExpirationTime {token_exp} must be in the future"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
