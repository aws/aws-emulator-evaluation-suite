"""delete-echoes-client-token-in-response."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-echoes-client-token-in-response"
GROUP = "state"
SERVICES = ["ssm-guiconnect"]

_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnectionRecordingPreferences returns the caller's ClientToken exactly even with
    nothing configured, as Delete is not gated by just-in-time node access, and a Get
    afterwards shows the account unconfigured."""
    guiconnect = ctx.client("ssm-guiconnect")

    token = ctx.unique_name("del-")[:64]
    resp = guiconnect.delete_connection_recording_preferences(ClientToken=token)
    assert resp["ClientToken"] == token, f"expected echoed token {token!r}, got {resp.get('ClientToken')!r}"

    get_code, get_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert get_code == "ResourceNotFoundException", (
        f"expected unconfigured state after Delete, but Get returned {get_code}"
    )
    assert get_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {get_message!r}"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
