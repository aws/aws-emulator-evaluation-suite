"""get-token-after-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-token-after-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["amplifybackend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A challenge token consumed via DeleteToken can no longer be retrieved via GetToken (ResourceNotFoundException)."""
    app_id = _create_amplify_app(ctx)
    ab = ctx.client("amplifybackend")

    created = ab.create_token(AppId=app_id)
    session_id = created["SessionId"]

    # Positive control: the freshly created session is retrievable.
    before = ab.get_token(AppId=app_id, SessionId=session_id)
    assert before["SessionId"] == session_id
    assert before["ChallengeCode"] == created["ChallengeCode"]

    deleted = ab.delete_token(AppId=app_id, SessionId=session_id)
    assert deleted["IsSuccess"] is True

    error = _client_error(lambda: ab.get_token(AppId=app_id, SessionId=session_id))
    assert error["Code"] == "ResourceNotFoundException", repr(error)
    assert error.get("Message") == (
        "An error occurred while processing your request: Login code not found"
    ), repr(error)


def _create_amplify_app(ctx):
    amplify = ctx.client("amplify")
    resp = amplify.create_app(name=ctx.unique_name("sim2real-ab-app-"), tags={"sim2real": CHECK})
    app_id = resp["app"]["appId"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
    return app_id


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError; call succeeded unexpectedly with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
