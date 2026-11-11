"""register-deregister-maintenance-window-target."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-deregister-maintenance-window-target"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a target makes it visible; deregistering removes it, and re-deregistering the
    same dead target id is a no-op rather than resurrecting it."""

    ssm = ctx.client("ssm")

    def _track_window(window_id):
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
        return window_id

    name = ctx.unique_name("sim2real-behav-probe-mw-target-")
    window_id = ssm.create_maintenance_window(
        Name=name,
        Schedule="rate(1 day)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    _track_window(window_id)

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "tag:Name", "Values": ["probe"]}],
    )["WindowTargetId"]

    listed = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert any(t["WindowTargetId"] == target_id for t in listed), "target should be listed after registration"

    ssm.deregister_target_from_maintenance_window(WindowId=window_id, WindowTargetId=target_id)

    listed_after = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert all(t["WindowTargetId"] != target_id for t in listed_after), (
        "target should be gone after deregistration"
    )

    ssm.deregister_target_from_maintenance_window(WindowId=window_id, WindowTargetId=target_id)

    listed_after_second = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert all(t["WindowTargetId"] != target_id for t in listed_after_second), (
        "a re-deregistered dead target id must not have been resurrected"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
