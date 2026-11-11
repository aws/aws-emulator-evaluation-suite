"""notify-recommendations-received-nonexistent-assistant-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "notify-recommendations-received-nonexistent-assistant-rejected"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """NotifyRecommendationsReceived against an assistantId that does not exist is rejected with
    ResourceNotFoundException, while the same call shape against a real assistant/session
    (positive control) succeeds."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT", tags={"sim2real-behav": "true"}
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    session = wisdom.create_session(assistantId=assistant_id, name=ctx.unique_name("sim2real-behav-session-"))[
        "session"
    ]
    session_id = session["sessionId"]

    fake_assistant_id = "00000000-0000-0000-0000-000000000000"
    assert fake_assistant_id != assistant_id, "fake assistant id collided with the created assistant"

    code, message = _error(
        lambda: wisdom.notify_recommendations_received(
            assistantId=fake_assistant_id, sessionId=session_id, recommendationIds=["11111111-1111-1111-1111-111111111111"]
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent assistantId, got {code!r}"
    assert message == "Assistant does not exist.", f"expected the assistant not-found message, got {message!r}"

    # positive control: the identical call against the real assistant/session is accepted (no
    # ResourceNotFoundException) — an unrecognized assistantId is a hard failure, but an
    # unrecognized recommendationId against a real assistant/session is only a soft
    # per-recommendation error in the 200 response
    ok = wisdom.notify_recommendations_received(
        assistantId=assistant_id, sessionId=session_id, recommendationIds=["11111111-1111-1111-1111-111111111111"]
    )
    reported_ids = {e.get("recommendationId") for e in ok.get("errors", [])}
    assert reported_ids == {"11111111-1111-1111-1111-111111111111"}, (
        f"expected a per-recommendation error naming the unrecognized recommendation id, got {ok.get('errors')!r}"
    )
    assert all(e.get("message") for e in ok["errors"]), f"expected a non-empty message per error, got {ok['errors']!r}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
