"""delete-token-unknown-session-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-token-unknown-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifybackend"]
INVALID_APP_ID = "An error occurred while processing your request: Invalid appId passed."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteToken succeeds for a real session and for an unknown session on a live app, but once the
    app is deleted it is refused with ValidationException and the exact message: AWS validates the
    app, not the session."""
    app_id = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")
    amplify = ctx.client("amplify")

    created = ab.create_token(AppId=app_id)
    session_id = created["SessionId"]

    # Positive control: deleting the real, existing session succeeds.
    deleted = ab.delete_token(AppId=app_id, SessionId=session_id)
    assert deleted["IsSuccess"] is True, f"expected IsSuccess=True deleting a real session, got {deleted!r}"

    # AWS does not verify session existence on delete: an unknown session on a live app succeeds.
    unknown_session_result = ab.delete_token(AppId=app_id, SessionId="00000000-0000-0000-0000-000000000000")
    assert unknown_session_result["IsSuccess"] is True, (
        f"expected IsSuccess=True for an unknown session on a live app, got {unknown_session_result!r}"
    )

    # Once the app is deleted, DeleteToken against its AppId is refused with ValidationException;
    # the app-identity check does not tell "never existed" from "malformed".
    amplify.delete_app(appId=app_id)

    error = _client_error(lambda: ab.delete_token(AppId=app_id, SessionId=session_id))
    assert error["Code"] == "ValidationException", repr(error)
    assert error.get("Message") == INVALID_APP_ID, repr(error)


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"))
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: _best_effort_delete_app(amplify, app_id))
    return app_id


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


