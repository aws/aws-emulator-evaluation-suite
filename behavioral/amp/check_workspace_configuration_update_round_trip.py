"""workspace-configuration-update-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workspace-configuration-update-round-trip"
GROUP = "data-plane"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkspaceConfiguration persists retentionPeriodInDays/outOfOrderTimeWindowInSeconds
    and DescribeWorkspaceConfiguration reflects the new values once ACTIVE."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"))["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    baseline = amp.describe_workspace_configuration(workspaceId=workspace_id)["workspaceConfiguration"]
    assert baseline["status"]["statusCode"] == "ACTIVE", (
        f"expected fresh workspace configuration to be ACTIVE, got {baseline['status']['statusCode']!r}"
    )

    new_retention = 45
    new_ooo_window = 300
    assert baseline["retentionPeriodInDays"] != new_retention, (
        "test value collides with the baseline default; the update would be a no-op"
    )
    assert baseline["outOfOrderTimeWindowInSeconds"] != new_ooo_window, (
        "test value collides with the baseline default; the update would be a no-op"
    )
    amp.update_workspace_configuration(
        workspaceId=workspace_id,
        retentionPeriodInDays=new_retention,
        outOfOrderTimeWindowInSeconds=new_ooo_window,
    )

    status = _poll_until(
        lambda: amp.describe_workspace_configuration(workspaceId=workspace_id)["workspaceConfiguration"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"workspace configuration update did not settle ACTIVE, got {status!r}"

    updated = amp.describe_workspace_configuration(workspaceId=workspace_id)["workspaceConfiguration"]
    assert updated["retentionPeriodInDays"] == new_retention, (
        f"expected retentionPeriodInDays={new_retention}, got {updated['retentionPeriodInDays']!r}"
    )
    assert updated["outOfOrderTimeWindowInSeconds"] == new_ooo_window, (
        f"expected outOfOrderTimeWindowInSeconds={new_ooo_window}, got {updated['outOfOrderTimeWindowInSeconds']!r}"
    )


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
