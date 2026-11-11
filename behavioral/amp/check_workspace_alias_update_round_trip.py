"""workspace-alias-update-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workspace-alias-update-round-trip"
GROUP = "state"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkspaceAlias changes the alias visible on DescribeWorkspace while leaving the
    workspaceId/arn untouched."""
    amp = ctx.client("amp")
    original_alias = ctx.unique_name("sim2real-amp-ws-orig-")
    workspace_id = amp.create_workspace(
        alias=original_alias, tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    original_arn = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["arn"]

    new_alias = ctx.unique_name("sim2real-amp-ws-new-")
    amp.update_workspace_alias(workspaceId=workspace_id, alias=new_alias)

    updated_alias = _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["alias"],
        lambda a: a == new_alias,
        timeout_s=60,
    )
    described = amp.describe_workspace(workspaceId=workspace_id)["workspace"]
    assert updated_alias == new_alias
    assert described["workspaceId"] == workspace_id
    assert described["arn"] == original_arn
    assert described["status"]["statusCode"] == "ACTIVE"


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
