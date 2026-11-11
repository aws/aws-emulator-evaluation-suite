"""delete-maintenance-window-then-get-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-maintenance-window-then-get-fails"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """State machine: after DeleteMaintenanceWindow, both the independent read
    (GetMaintenanceWindow) and a mutation (UpdateMaintenanceWindow) against the
    dead id must fail with DoesNotExistException."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected ClientError, call unexpectedly succeeded")

    name = ctx.unique_name("sim2real-behav-probe-mw-delete-")

    window_id = ssm.create_maintenance_window(
        Name=name,
        Schedule="rate(1 day)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
    )["WindowId"]

    # Positive control: the window is live and independently readable before it is touched.
    live = ssm.get_maintenance_window(WindowId=window_id)
    assert live["WindowId"] == window_id, live

    ssm.delete_maintenance_window(WindowId=window_id)

    code, message = _error_code(lambda: ssm.get_maintenance_window(WindowId=window_id))
    assert code == "DoesNotExistException", (
        f"expected DoesNotExistException after delete, got {code!r}"
    )
    assert message == f"Maintenance window {window_id} does not exist", message

    # A mutation against the dead id must fail the same way, not just the read.
    update_code, update_message = _error_code(
        lambda: ssm.update_maintenance_window(WindowId=window_id, Description="post-delete")
    )
    assert update_code == "DoesNotExistException", (
        f"expected DoesNotExistException on UpdateMaintenanceWindow after delete, got {update_code!r}"
    )
    assert update_message == f"Maintenance window {window_id} does not exist", update_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
