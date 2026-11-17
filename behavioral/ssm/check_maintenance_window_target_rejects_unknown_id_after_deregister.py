"""maintenance-window-target-rejects-unknown-id-after-deregister."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-target-rejects-unknown-id-after-deregister"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deregistered maintenance window target is gone from DescribeMaintenanceWindowTargets, and
    UpdateMaintenanceWindowTarget on its dead id fails with DoesNotExistException, though the
    identical update succeeded while the target was still live."""
    ssm = ctx.client("ssm")
    window_name = ctx.unique_name("sim2real-mw-target-notfound-")

    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule="rate(30 days)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
        Description="probe target",
    )["WindowTargetId"]

    # Positive control: updating the live target succeeds and is visible on a read.
    ssm.update_maintenance_window_target(
        WindowId=window_id, WindowTargetId=target_id, Description="probe target updated"
    )
    targets = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    live = next(t for t in targets if t["WindowTargetId"] == target_id)
    assert live["Description"] == "probe target updated", live

    ssm.deregister_target_from_maintenance_window(WindowId=window_id, WindowTargetId=target_id)
    remaining = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert all(t["WindowTargetId"] != target_id for t in remaining), remaining

    # Dead means unusable: an independent mutation on the dead id fails, specifically.
    update_code, update_message = _error_code(
        lambda: ssm.update_maintenance_window_target(
            WindowId=window_id, WindowTargetId=target_id, Description="should not apply"
        )
    )
    assert update_code == "DoesNotExistException", update_code
    assert update_message == f"Maintenance window target {target_id} does not exist", update_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
