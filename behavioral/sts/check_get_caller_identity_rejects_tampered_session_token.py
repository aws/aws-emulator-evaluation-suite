"""get-caller-identity-rejects-tampered-session-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-caller-identity-rejects-tampered-session-token"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_INVALID_TOKEN_MESSAGE = "The security token included in the request is invalid"


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a tampered session token with InvalidClientTokenId, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _client_for(ctx, creds: dict):
    """A client signed with the given temporary credentials."""
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A genuinely issued temporary session, with one character flipped inside its session
    token, is rejected InvalidClientTokenId rather than being honoured as the issuing identity.
    """
    sts = ctx.client("sts")
    issued = sts.get_session_token(DurationSeconds=900)["Credentials"]

    def _identity(response: dict) -> dict:
        return {k: response[k] for k in ("Arn", "Account", "UserId")}

    # Positive control: the untampered session authenticates fine.
    live_client = _client_for(ctx, issued)
    control = _identity(live_client.get_caller_identity())
    assert control["Account"], f"positive control failed: {control!r}"

    token = issued["SessionToken"]
    mid = len(token) // 2
    tampered_char = "X" if token[mid] != "X" else "Y"
    tampered_token = token[:mid] + tampered_char + token[mid + 1 :]
    assert tampered_token != token, "tampering the session token was a no-op"

    tampered_client = _client_for(ctx, dict(issued, SessionToken=tampered_token))
    code, message = _error(tampered_client.get_caller_identity)
    assert code == "InvalidClientTokenId", (
        f"expected InvalidClientTokenId for a tampered session token, got {code!r}"
    )
    assert message == _INVALID_TOKEN_MESSAGE, message

    # The untampered session is still honoured: the rejection is specific to the tampered
    # token, not a side effect that broke the whole session.
    restored = _identity(live_client.get_caller_identity())
    assert restored == control, (
        f"the untampered session stopped authenticating after the tampered one was refused: "
        f"expected {control!r}, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
