"""workspace-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workspace-delete-lifecycle"
GROUP = "state"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWorkspace moves an ACTIVE workspace through DELETING to removed (404 on describe)."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: _delete_if_present(amp, workspace_id))

    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    amp.delete_workspace(workspaceId=workspace_id)

    code, message = _error(lambda: amp.describe_workspace(workspaceId=workspace_id), wait_s=180)
    assert code == "ResourceNotFoundException", f"expected the deleted workspace to 404 on describe, got {code!r}"
    expected = "Workspace not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Gone means unusable, not just unlisted: a mutation on the same dead id is rejected too.
    delete_again_code, message = _error(lambda: amp.delete_workspace(workspaceId=workspace_id))
    assert delete_again_code == "ResourceNotFoundException", (
        f"expected a second delete on the gone workspace to 404, got {delete_again_code!r}"
    )
    expected = "Workspace not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _delete_if_present(amp, workspace_id):
    """Teardown for a workspace the check itself deletes: an already-gone one is the goal state."""
    from botocore.exceptions import ClientError

    try:
        amp.delete_workspace(workspaceId=workspace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
