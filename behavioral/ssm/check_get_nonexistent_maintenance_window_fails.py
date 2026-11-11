"""get-nonexistent-maintenance-window-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-maintenance-window-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: GetMaintenanceWindow on a fabricated WindowId must fail,
    while a real window created moments earlier still resolves fine (positive control)."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected DoesNotExistException, but the call SUCCEEDED and returned {result!r}"
        )

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-behav-probe-mw-get-"),
        Schedule="rate(1 day)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=False,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # Positive control: a real, valid read against the window we just created must succeed.
    control = ssm.get_maintenance_window(WindowId=window_id)
    assert control["WindowId"] == window_id, (
        f"expected the just-created window {window_id!r} to resolve, got {control.get('WindowId')!r}"
    )

    code, message = _error_code(lambda: ssm.get_maintenance_window(WindowId="mw-00000000000000000"))
    assert code == "DoesNotExistException", f"expected DoesNotExistException, got {code!r}"
    assert message == "Maintenance window mw-00000000000000000 does not exist", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
