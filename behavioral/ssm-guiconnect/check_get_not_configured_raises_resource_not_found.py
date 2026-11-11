"""get-not-configured-raises-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-not-configured-raises-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["ssm-guiconnect"]

_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get on an account/region with no recording preferences configured raises
    ResourceNotFoundException, consistently across repeated calls (a pure read), and the error
    envelope is well-formed: a Message string plus a RequestId in ResponseMetadata."""
    guiconnect = ctx.client("ssm-guiconnect")
    _force_unset(guiconnect)

    error1 = _client_error(lambda: guiconnect.get_connection_recording_preferences())
    code1 = error1.response["Error"]["Code"]
    assert code1 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code1}"
    message1 = error1.response["Error"].get("Message")
    assert message1 == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {message1!r}"
    assert error1.response.get("ResponseMetadata", {}).get("RequestId"), (
        "expected a RequestId in ResponseMetadata on the error response"
    )

    error2 = _client_error(lambda: guiconnect.get_connection_recording_preferences())
    code2 = error2.response["Error"]["Code"]
    assert code2 == "ResourceNotFoundException", f"second Get gave {code2}, must be stable"
    message2 = error2.response["Error"].get("Message")
    assert message2 == _NOT_FOUND, f"second Get message {message2!r} must be stable"


def _client_error(fn):
    """The ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e
    raise AssertionError("expected the call to be refused, but it succeeded")


def _force_unset(guiconnect) -> None:
    from botocore.exceptions import ClientError

    try:
        guiconnect.delete_connection_recording_preferences()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
