"""delete-not-configured-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-not-configured-is-idempotent"
GROUP = "representation"
SERVICES = ["ssm-guiconnect"]

_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Delete when nothing is configured is idempotent: repeated calls behave identically and never
    surface a spurious ConflictException or AccessDeniedException, Get still reports unset, and the
    response envelope on the successful path carries a well-formed ResponseMetadata/RequestId."""
    guiconnect = ctx.client("ssm-guiconnect")

    first_resp, first_code = _call(lambda: guiconnect.delete_connection_recording_preferences())
    assert first_code is None, (
        f"Delete is not gated by just-in-time node access and must succeed on an unconfigured "
        f"account, got error: {first_code}"
    )
    request_id = first_resp.get("ResponseMetadata", {}).get("RequestId")
    assert request_id, "a successful Delete response must carry a RequestId in ResponseMetadata"
    assert first_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200 on a successful Delete, got "
        f"{first_resp['ResponseMetadata'].get('HTTPStatusCode')}"
    )

    second_resp, second_code = _call(lambda: guiconnect.delete_connection_recording_preferences())
    assert second_code is None, (
        f"delete on an already-unset resource is not idempotent: first=None second={second_code}"
    )

    get_code, get_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert get_code == "ResourceNotFoundException", f"expected unset state after delete, got {get_code}"
    assert get_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {get_message!r}"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _call(fn):
    from botocore.exceptions import ClientError

    try:
        return fn(), None
    except ClientError as e:
        return None, e.response["Error"]["Code"]



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
