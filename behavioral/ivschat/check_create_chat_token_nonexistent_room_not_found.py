"""create-chat-token-nonexistent-room-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-chat-token-nonexistent-room-not-found"
GROUP = "errors"
SERVICES = ["ivschat"]


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChatToken against a well-formed but never-created room ARN fails with
    ResourceNotFoundException, and issuing a token against a real room in the same account
    still succeeds (control)."""
    ivschat = ctx.client("ivschat")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:ivschat:{ctx.region}:{account_id}:room/{ctx.unique_name('nonexist')[:20]}"

    code, message = _client_error(
        lambda: ivschat.create_chat_token(roomIdentifier=bogus_arn, userId="sim2real-user")
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created room, got {code!r}"
    )
    assert message == f"Resource: {bogus_arn} not found", f"unexpected message: {message!r}"

    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"), tags={"sim2real": "true"}
    )
    real_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=real_arn))
    control = ivschat.create_chat_token(roomIdentifier=real_arn, userId="sim2real-user")
    assert "token" in control and control["token"], (
        f"expected a non-empty token for a real room, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
