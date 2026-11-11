"""remove-all-backends-nonexistent-app-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-all-backends-nonexistent-app-not-found"
GROUP = "error-semantics"
SERVICES = ["amplifybackend"]
INVALID_APP_ID = "An error occurred while processing your request: Invalid appId passed."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveAllBackends on a live app with no backends echoes its AppId, while a deleted app's AppId
    and a malformed AppId are both refused with the same ValidationException and exact message."""
    amplify = ctx.client("amplify")
    ab = ctx.client("amplifybackend")

    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"))
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: _best_effort_delete_app(amplify, app_id))

    # Positive control: a live app with no backend environments is accepted, so the
    # boundary is app existence.
    live_result = ab.remove_all_backends(AppId=app_id)
    assert live_result["AppId"] == app_id, (
        f"expected RemoveAllBackends to echo AppId {app_id!r}, got {live_result.get('AppId')!r}"
    )

    amplify.delete_app(appId=app_id)

    error = _client_error(lambda: ab.remove_all_backends(AppId=app_id))
    assert error["Code"] == "ValidationException", repr(error)
    assert error.get("Message") == INVALID_APP_ID, repr(error)

    # A malformed AppId fails the same app-identity validation.
    error2 = _client_error(lambda: ab.remove_all_backends(AppId="not-a-valid-app-id!"), timeout_s=0)
    assert error2["Code"] == "ValidationException", repr(error2)
    assert error2.get("Message") == INVALID_APP_ID, repr(error2)


def _best_effort_delete_app(amplify, app_id):
    try:
        amplify.delete_app(appId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn, timeout_s=60.0, interval_s=3.0):
    """Return the botocore Error dict of fn()'s refusal, retrying while it still succeeds (the
    app deletion propagates asynchronously); raise if it never refuses within timeout_s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError within {timeout_s}s; call kept succeeding: {result!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

