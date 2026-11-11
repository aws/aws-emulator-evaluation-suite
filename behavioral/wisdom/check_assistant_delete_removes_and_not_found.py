"""assistant-delete-removes-and-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assistant-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAssistant removes the assistant; a subsequent GetAssistant returns
    ResourceNotFoundException, and a second DeleteAssistant on the same now-dead id
    also fails with ResourceNotFoundException rather than silently no-oping."""
    wisdom = ctx.client("wisdom")
    name = ctx.unique_name("sim2real-asst-")
    created = wisdom.create_assistant(name=name, type="AGENT")["assistant"]
    assistant_id = created["assistantId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    wisdom.delete_assistant(assistantId=assistant_id)
    _poll_not_found(lambda: wisdom.get_assistant(assistantId=assistant_id), timeout_s=60.0)

    error = _error(lambda: wisdom.get_assistant(assistantId=assistant_id))
    expected_error = ("ResourceNotFoundException", "Assistant does not exist.")
    assert error == expected_error, f"expected {expected_error!r}, got {error!r}"

    # mutation on the dead id also fails: a second delete must not silently no-op
    redelete = _error(lambda: wisdom.delete_assistant(assistantId=assistant_id))
    expected_redelete = ("ResourceNotFoundException", "Assistant does not exist.")
    assert redelete == expected_redelete, (
        f"expected a second DeleteAssistant on an already-deleted assistant to raise "
        f"{expected_redelete!r}, got {redelete!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _is_not_found(fn) -> bool:
    """True once fn() is refused with ResourceNotFoundException (polling only)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return False


def _delete_if_present(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_not_found(get_fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _is_not_found(get_fn):
            return
        time.sleep(interval_s)
    raise AssertionError("resource was not removed within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
