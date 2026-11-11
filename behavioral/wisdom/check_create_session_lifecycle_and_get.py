"""create-session-lifecycle-and-get."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-session-lifecycle-and-get"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession attaches a session to an assistant and GetSession returns matching fields;
    the session disappears once its parent assistant is deleted."""
    wisdom = ctx.client("wisdom")
    resource_tags = {"team": "support", "stage": "sim2real-behav"}
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT", tags=resource_tags
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    session_name = ctx.unique_name("sim2real-behav-session-")
    session = wisdom.create_session(
        assistantId=assistant_id, name=session_name, description="behav session", tags=resource_tags
    )["session"]
    session_id = session["sessionId"]

    assert session["name"] == session_name, f"expected created session name {session_name!r}, got {session['name']!r}"
    assert session["description"] == "behav session", (
        f"expected created session description 'behav session', got {session['description']!r}"
    )

    got = wisdom.get_session(assistantId=assistant_id, sessionId=session_id)["session"]
    assert got["sessionId"] == session_id, f"expected GetSession sessionId {session_id!r}, got {got['sessionId']!r}"
    assert got["name"] == session_name, f"expected GetSession name {session_name!r}, got {got['name']!r}"
    assert got["description"] == "behav session", (
        f"expected GetSession description 'behav session', got {got['description']!r}"
    )

    # the docstring's second half is otherwise untested: delete the parent assistant explicitly
    # and prove the session it owned is now unreachable through the same read used above.
    wisdom.delete_assistant(assistantId=assistant_id)
    code, message = _poll_error(
        lambda: wisdom.get_session(assistantId=assistant_id, sessionId=session_id),
        timeout_s=60.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected GetSession on a session whose parent assistant was deleted to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == "Assistant does not exist.", f"expected the assistant not-found message, got {message!r}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_error(fn, *, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it raises; return that ClientError's (code, message), or fail on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"expected an error within {timeout_s}s, but the call kept succeeding (last={last!r})")


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
