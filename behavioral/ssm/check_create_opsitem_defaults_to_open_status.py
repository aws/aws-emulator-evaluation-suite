"""create-opsitem-defaults-to-open-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-opsitem-defaults-to-open-status"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created OpsItem starts in the Open status."""

    ssm = ctx.client("ssm")

    def _track_ops_item(ops_item_id):
        ctx.on_cleanup(lambda: ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved"))
        return ops_item_id

    title = ctx.unique_name("sim2real-behav-probe-opsitem-")

    create_resp = ssm.create_ops_item(
        Title=title,
        Description="behavioral fidelity probe",
        Source="probe.simparity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ops_item_id = create_resp["OpsItemId"]
    _track_ops_item(ops_item_id)

    got = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert got["Status"] == "Open", f"expected Status=Open, got {got['Status']!r}"
    assert got["Title"] == title, f"expected Title={title!r}, got {got['Title']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
