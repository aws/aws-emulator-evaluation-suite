"""maintenance-window-execution-lookup-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-execution-lookup-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_DOES_NOT_EXIST_MESSAGE = "Resource does not exist in the data store."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMaintenanceWindowExecution/Task/TaskInvocation reject nonexistent ids with
    DoesNotExistException, and the Describe execution task/invocation listings for a
    nonexistent execution return empty lists."""
    ssm = ctx.client("ssm")
    window_name = ctx.unique_name("sim2real-mw-lookup-")

    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule="rate(30 days)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # Positive control: a real, valid read against the window we just created must
    # succeed, so the DoesNotExistException asserted below can be attributed to the
    # fabricated ID rather than to SSM rejecting everything in this account.
    control = ssm.get_maintenance_window(WindowId=window_id)
    assert control["WindowId"] == window_id, (
        f"positive control failed: GetMaintenanceWindow on the just-created window "
        f"{window_id} did not echo its own WindowId, got {control!r}"
    )

    fake_execution_id = str(uuid.uuid4())
    fake_task_id = str(uuid.uuid4())
    fake_invocation_id = str(uuid.uuid4())

    exec_code, exec_message = _error(
        lambda: ssm.get_maintenance_window_execution(WindowExecutionId=fake_execution_id)
    )
    assert exec_code == "DoesNotExistException", (
        f"expected DoesNotExistException from GetMaintenanceWindowExecution for a "
        f"nonexistent WindowExecutionId, got {exec_code}"
    )
    assert exec_message == _DOES_NOT_EXIST_MESSAGE, exec_message

    task_code, task_message = _error(
        lambda: ssm.get_maintenance_window_execution_task(
            WindowExecutionId=fake_execution_id, TaskId=fake_task_id
        )
    )
    assert task_code == "DoesNotExistException", (
        f"expected DoesNotExistException from GetMaintenanceWindowExecutionTask for "
        f"a nonexistent execution/task pair, got {task_code}"
    )
    assert task_message == _DOES_NOT_EXIST_MESSAGE, task_message

    invocation_code, invocation_message = _error(
        lambda: ssm.get_maintenance_window_execution_task_invocation(
            WindowExecutionId=fake_execution_id,
            TaskId=fake_task_id,
            InvocationId=fake_invocation_id,
        )
    )
    assert invocation_code == "DoesNotExistException", (
        f"expected DoesNotExistException from GetMaintenanceWindowExecutionTaskInvocation "
        f"for a nonexistent execution/task/invocation triple, got {invocation_code}"
    )
    assert invocation_message == _DOES_NOT_EXIST_MESSAGE, invocation_message

    tasks = ssm.describe_maintenance_window_execution_tasks(
        WindowExecutionId=fake_execution_id
    )["WindowExecutionTaskIdentities"]
    assert tasks == [], (
        f"expected DescribeMaintenanceWindowExecutionTasks for a nonexistent "
        f"execution to return an empty list, got {tasks}"
    )

    invocations = ssm.describe_maintenance_window_execution_task_invocations(
        WindowExecutionId=fake_execution_id, TaskId=fake_task_id
    )["WindowExecutionTaskInvocationIdentities"]
    assert invocations == [], (
        f"expected DescribeMaintenanceWindowExecutionTaskInvocations for a "
        f"nonexistent execution/task to return an empty list, got {invocations}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected a ClientError but the call succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

