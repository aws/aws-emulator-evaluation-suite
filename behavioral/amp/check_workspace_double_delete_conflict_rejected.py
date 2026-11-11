"""workspace-double-delete-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workspace-double-delete-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["amp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteWorkspace on an already-DELETING workspace is rejected as a wrong-status
    transition (ConflictException), while a fresh ACTIVE workspace deletes cleanly (control)."""
    amp = ctx.client("amp")

    # Setup: a workspace we will race deletes against.
    target_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-target-"))["workspaceId"]
    ctx.on_cleanup(lambda: _delete_ignoring_terminal(amp, target_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=target_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    # Break exactly one thing: delete once (moves to DELETING), then delete again immediately.
    amp.delete_workspace(workspaceId=target_id)
    code, message = _error(lambda: amp.delete_workspace(workspaceId=target_id))
    assert code == "ConflictException", f"expected ConflictException on double-delete, got {code}"
    expected = "Can't delete workspace in non-ACTIVE state. Current status is DELETING"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the workspace is still on its way out (DELETING or gone), never resurrected
    # to ACTIVE by the rejected second call.
    status_after = _error_code_or_status(amp, target_id)
    assert status_after in ("DELETING", "NotFound"), f"unexpected post-conflict state: {status_after}"

    # Positive control: a separate, freshly-created ACTIVE workspace deletes without conflict.
    control_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-control-"))["workspaceId"]
    ctx.on_cleanup(lambda: _delete_ignoring_terminal(amp, control_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=control_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    amp.delete_workspace(workspaceId=control_id)
    control_code, control_message = _error(lambda: amp.describe_workspace(workspaceId=control_id), wait_s=180)
    assert control_code == "ResourceNotFoundException", (
        f"expected the control workspace to disappear with ResourceNotFoundException, "
        f"got {control_code!r}"
    )
    expected = "Workspace not found"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"


def _error(fn, *, wait_s=0.0, interval_s=3.0):
    """Call fn(), which must fail; return its botocore error (code, message). With wait_s a
    success is retried until the refusal appears, and a success past the deadline raises, so a
    target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _delete_ignoring_terminal(amp, workspace_id):
    from botocore.exceptions import ClientError

    try:
        amp.delete_workspace(workspaceId=workspace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _error_code_or_status(amp, workspace_id):
    from botocore.exceptions import ClientError

    try:
        return amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "NotFound"
        raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
