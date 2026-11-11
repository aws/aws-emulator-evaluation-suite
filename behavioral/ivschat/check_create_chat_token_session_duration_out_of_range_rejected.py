"""create-chat-token-session-duration-out-of-range-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "create-chat-token-session-duration-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivschat"]


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects sessionDurationInMinutes=181, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChatToken refuses sessionDurationInMinutes above 180 with ValidationException and the exact message,
    while 180 returns a token whose sessionExpirationTime is about 180 minutes out."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"),
        tags={"sim2real-check": CHECK},
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    code, message = _error_code(
        lambda: ivschat.create_chat_token(
            roomIdentifier=room_arn, userId="sim2real-user", sessionDurationInMinutes=181
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "CreateChatToken.sessionDurationInMinutes is required to have a maximum value of 180.0, "
        "found 181.0"
    ), f"unexpected message: {message!r}"

    before = datetime.now(timezone.utc)
    control = ivschat.create_chat_token(
        roomIdentifier=room_arn, userId="sim2real-user", sessionDurationInMinutes=180
    )
    after = datetime.now(timezone.utc)
    assert "token" in control and control["token"], f"expected a token, got {control!r}"

    session_exp = control["sessionExpirationTime"]
    expected_low = before + timedelta(minutes=180) - timedelta(seconds=30)
    expected_high = after + timedelta(minutes=180) + timedelta(seconds=30)
    assert expected_low <= session_exp <= expected_high, (
        f"sessionExpirationTime {session_exp} not within 180min of request time "
        f"({expected_low}..{expected_high}) — the boundary value must be honored, not clamped"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
