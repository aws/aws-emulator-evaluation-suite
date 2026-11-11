"""workspace-create-active-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workspace-create-active-lifecycle"
GROUP = "state"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkspace transitions CREATING -> ACTIVE and DescribeWorkspace reflects it."""
    amp = ctx.client("amp")
    alias = ctx.unique_name("sim2real-amp-ws-")
    created = amp.create_workspace(alias=alias, tags={"sim2real-owner": "behavioral"})
    workspace_id = created["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))

    created_status = created["status"]["statusCode"]
    assert created_status in ("CREATING", "ACTIVE"), (
        f"expected CreateWorkspace statusCode in (CREATING, ACTIVE), got {created_status!r}"
    )

    status = _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "ACTIVE", f"workspace ended in {status}, not ACTIVE"

    described = amp.describe_workspace(workspaceId=workspace_id)["workspace"]
    assert described["workspaceId"] == workspace_id, (
        f"expected describe_workspace to echo workspaceId {workspace_id!r}, got {described['workspaceId']!r}"
    )
    assert described["alias"] == alias, f"expected alias {alias!r}, got {described['alias']!r}"
    assert described["arn"].endswith(workspace_id), (
        f"expected arn to end with workspaceId {workspace_id!r}, got {described['arn']!r}"
    )
    assert described["prometheusEndpoint"], "expected a non-empty prometheusEndpoint on an ACTIVE workspace"


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
