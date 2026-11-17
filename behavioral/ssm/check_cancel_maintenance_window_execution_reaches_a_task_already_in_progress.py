"""cancel-maintenance-window-execution-reaches-a-task-already-in-progress."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "cancel-maintenance-window-execution-reaches-a-task-already-in-progress"
GROUP = "state-machine"
SERVICES = ["ssm", "lambda", "iam"]

_RUNNING_TASK_STATUSES = {"PENDING", "IN_PROGRESS"}
_TERMINAL_EXECUTION_STATUSES = {
    "SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED", "SKIPPED_OVERLAPPING",
}
_TERMINAL_TASK_STATUSES = {"SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED", "SKIPPED"}

_SLOW_HANDLER_SRC = (
    "import time\n"
    "def handler(event, context):\n"
    "    time.sleep(45)\n"
    "    return {'ok': True}\n"
)
_FAST_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)

_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
)

_LAMBDA_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelMaintenanceWindowExecution marks both the task already IN_PROGRESS and the
    lower-priority task still queued behind it CANCELLED, and the execution itself
    reaches the terminal state CANCELLED.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CancelMaintenanceWindowExecution.html
    """
    ssm = ctx.client("ssm")
    lambda_client = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _build_lambda_role(ctx, iam)
    slow_fn_arn = _build_lambda_function(ctx, lambda_client, role_arn, "slow", _SLOW_HANDLER_SRC)
    fast_fn_arn = _build_lambda_function(ctx, lambda_client, role_arn, "fast", _FAST_HANDLER_SRC)

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mwcancel-"),
        Schedule="cron(0/1 * * * ? *)",
        Duration=2,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # Priority 1 runs first and holds the window open for its whole 45-second sleep; priority 2
    # is only dispatched once every priority-1 task has finished.
    ssm.register_task_with_maintenance_window(
        WindowId=window_id, TaskArn=slow_fn_arn, TaskType="LAMBDA", Priority=1,
        TaskInvocationParameters={"Lambda": {"Payload": b"{}"}},
    )
    ssm.register_task_with_maintenance_window(
        WindowId=window_id, TaskArn=fast_fn_arn, TaskType="LAMBDA", Priority=2,
        TaskInvocationParameters={"Lambda": {"Payload": b"{}"}},
    )

    execution_id = _poll_until(
        lambda: _first_execution_id(ssm, window_id),
        lambda v: v is not None,
        timeout_s=360,
        interval_s=10,
    )
    assert execution_id is not None, "the cron-scheduled window never produced an execution"

    slow_task_id = _poll_until(
        lambda: _task_id_for_arn(ssm, execution_id, slow_fn_arn),
        lambda v: v is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert slow_task_id is not None, "the priority-1 task never appeared in the execution's task list"

    started = _poll_until(
        lambda: ssm.get_maintenance_window_execution_task(
            WindowExecutionId=execution_id, TaskId=slow_task_id
        ).get("Status"),
        lambda status: status == "IN_PROGRESS" or status in _TERMINAL_TASK_STATUSES,
        timeout_s=60,
        interval_s=2,
    )
    assert started == "IN_PROGRESS", (
        f"expected the 45-second priority-1 task to be IN_PROGRESS when observed, got {started!r}"
    )

    ssm.cancel_maintenance_window_execution(WindowExecutionId=execution_id)

    slow_final = _poll_until(
        lambda: ssm.get_maintenance_window_execution_task(
            WindowExecutionId=execution_id, TaskId=slow_task_id
        ).get("Status"),
        lambda status: status in _TERMINAL_TASK_STATUSES,
        timeout_s=120,
        interval_s=5,
    )
    assert slow_final == "CANCELLED", (
        f"the task already IN_PROGRESS when cancel was issued ended {slow_final!r}, expected CANCELLED"
    )

    fast_task_id = _task_id_for_arn(ssm, execution_id, fast_fn_arn)
    if fast_task_id is not None:
        fast_status = ssm.get_maintenance_window_execution_task(
            WindowExecutionId=execution_id, TaskId=fast_task_id
        )["Status"]
        assert fast_status == "CANCELLED", (
            f"the lower-priority task, queued behind the one that was IN_PROGRESS at cancel "
            f"time, reports {fast_status!r}, expected CANCELLED"
        )
        invocations = ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=execution_id, TaskId=fast_task_id
        )["WindowExecutionTaskInvocationIdentities"]
        invoked_statuses = {inv["Status"] for inv in invocations}
        assert not invoked_statuses & {"SUCCESS", "IN_PROGRESS"}, (
            f"the lower-priority task's invocation record(s) show {invocations}; "
            "the Lambda function must never have actually been invoked"
        )

    execution_final = _poll_until(
        lambda: ssm.get_maintenance_window_execution(WindowExecutionId=execution_id).get("Status"),
        lambda status: status in _TERMINAL_EXECUTION_STATUSES,
        timeout_s=60,
        interval_s=3,
    )
    assert execution_final == "CANCELLED", (
        f"the window execution ended {execution_final!r} after being cancelled, expected CANCELLED"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _first_execution_id(ssm, window_id):
    executions = ssm.describe_maintenance_window_executions(WindowId=window_id)["WindowExecutions"]
    return executions[0]["WindowExecutionId"] if executions else None


def _task_id_for_arn(ssm, execution_id, task_arn):
    tasks = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=execution_id)["WindowExecutionTaskIdentities"]
    match = next((t for t in tasks if t["TaskArn"] == task_arn), None)
    return match["TaskExecutionId"] if match else None


def _build_lambda_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-mwcancel-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC_EXEC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC_EXEC_POLICY_ARN)
    )
    return role_arn


def _build_lambda_function(ctx, lambda_client, role_arn, suffix, handler_src):
    # Amazon Web Services' managed maintenance-window role only grants lambda:InvokeFunction on
    # function names starting with the literal "SSM".
    fn_name = ctx.unique_name(f"SSMsim2real-mwcancel-{suffix}-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_src)

    deadline = time.monotonic() + 90
    fn_arn = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            fn_arn = lambda_client.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=60,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    assert fn_arn is not None, f"the Lambda role never became assumable in time: {last_err}"
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}"))
    return fn_arn


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """A Lambda invocation's buffered log stream can flush after delete_function and recreate
    the log group, so one delete is not enough: delete until it stays gone."""
    deadline = time.monotonic() + budget_s
    absent_reads = 0
    while absent_reads < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent_reads = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except logs.exceptions.ResourceNotFoundException:
                pass
        else:
            absent_reads += 1
        if absent_reads < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name} still reappearing after {budget_s}s of deletes")
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
