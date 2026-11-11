"""update-opsitem-status-transition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-opsitem-status-transition"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOpsItem can transition Status from Open to InProgress to Resolved."""

    ssm = ctx.client("ssm")

    def _track_ops_item(ops_item_id):
        ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))
        return ops_item_id

    title = ctx.unique_name("sim2real-behav-probe-opsitem-transition-")

    ops_item_id = ssm.create_ops_item(
        Title=title,
        Description="behavioral fidelity probe",
        Source="probe.simparity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpsItemId"]
    _track_ops_item(ops_item_id)

    ssm.update_ops_item(OpsItemId=ops_item_id, Status="InProgress")
    in_progress = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert in_progress["Status"] == "InProgress", (
        f"expected Status=InProgress after transition, got {in_progress['Status']!r}"
    )

    ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved")
    resolved = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert resolved["Status"] == "Resolved", (
        f"expected Status=Resolved after transition, got {resolved['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
