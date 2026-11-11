"""create-maintenance-window-and-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-maintenance-window-and-get"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMaintenanceWindow returns a WindowId that GetMaintenanceWindow can resolve."""

    ssm = ctx.client("ssm")

    def _track_window(window_id):
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
        return window_id

    name = ctx.unique_name("sim2real-behav-probe-mw-")

    create_resp = ssm.create_maintenance_window(
        Name=name,
        Schedule="rate(1 day)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    window_id = create_resp["WindowId"]
    _track_window(window_id)

    got = ssm.get_maintenance_window(WindowId=window_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Schedule"] == "rate(1 day)", (
        f"expected Schedule 'rate(1 day)', got {got['Schedule']!r}"
    )
    assert got["Enabled"] is True, "a newly created window should be enabled by default"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
