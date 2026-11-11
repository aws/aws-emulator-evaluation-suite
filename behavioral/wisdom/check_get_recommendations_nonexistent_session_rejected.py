"""get-recommendations-nonexistent-session-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-recommendations-nonexistent-session-rejected"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRecommendations does not validate sessionId: a well-formed unknown sessionId returns an empty
    recommendations list, and a real session's call returns a list.
    """
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-behav-asst-"),
        type="AGENT",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    session = wisdom.create_session(assistantId=assistant_id, name=ctx.unique_name("sim2real-behav-session-"))[
        "session"
    ]
    real_session_id = session["sessionId"]
    fake_session_id = "00000000-0000-0000-0000-000000000000"
    assert fake_session_id != real_session_id, (
        f"fixture bug: fake session id {fake_session_id!r} collided with the real one"
    )

    unknown = wisdom.get_recommendations(assistantId=assistant_id, sessionId=fake_session_id)
    assert unknown["recommendations"] == [], (
        f"expected an unknown sessionId to return an empty recommendations list without raising, "
        f"got {unknown['recommendations']!r}"
    )

    # positive control: the real session is queryable without error, on the same call shape
    ok = wisdom.get_recommendations(assistantId=assistant_id, sessionId=real_session_id)
    assert isinstance(ok["recommendations"], list), (
        f"expected a list of recommendations for the real session, got {ok['recommendations']!r}"
    )


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
