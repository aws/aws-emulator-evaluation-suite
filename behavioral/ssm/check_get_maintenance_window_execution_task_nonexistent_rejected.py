"""get-maintenance-window-execution-task-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-maintenance-window-execution-task-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMaintenanceWindowExecutionTask for a well-formed but unknown
    WindowExecutionId/TaskId combination is rejected with DoesNotExistException, while a
    real read against a genuine maintenance window (the positive control) still succeeds."""
    ssm = ctx.client("ssm")

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0 12 * * ? *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # Positive control: a real, valid read against the window we just created must succeed.
    control = ssm.describe_maintenance_window_executions(WindowId=window_id)
    assert "WindowExecutions" in control, f"expected WindowExecutions in response, got {control!r}"

    fake_execution_id = str(uuid.uuid4())
    fake_task_id = str(uuid.uuid4())

    def _call():
        ssm.get_maintenance_window_execution_task(
            WindowExecutionId=fake_execution_id, TaskId=fake_task_id
        )

    err = _error(_call)
    assert err["Code"] == "DoesNotExistException", f"expected DoesNotExistException, got {err!r}"
    expected_message = "Resource does not exist in the data store."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a fabricated id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
