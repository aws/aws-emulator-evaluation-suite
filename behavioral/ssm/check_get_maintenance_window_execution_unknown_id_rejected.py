"""get-maintenance-window-execution-unknown-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-maintenance-window-execution-unknown-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMaintenanceWindowExecution with a fabricated WindowExecutionId raises
    DoesNotExistException, while the parent maintenance window it was fabricated
    against still resolves fine."""
    ssm = ctx.client("ssm")
    window_name = ctx.unique_name("sim2real-ssm-mw-")
    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule="cron(0 12 * * ? *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # Positive control: the real window resolves fine.
    positive = ssm.get_maintenance_window(WindowId=window_id)
    assert positive["WindowId"] == window_id, (
        f"positive control failed: expected WindowId {window_id!r}, got {positive['WindowId']!r}"
    )

    fake_execution_id = str(uuid.uuid4())

    def _call():
        ssm.get_maintenance_window_execution(WindowExecutionId=fake_execution_id)

    err = _error(_call)
    assert err["Code"] == "DoesNotExistException", f"expected DoesNotExistException, got {err!r}"
    expected_message = "Resource does not exist in the data store."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects GetMaintenanceWindowExecution for a fabricated id, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
