"""maintenance-window-execution-task-invocation-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "maintenance-window-execution-task-invocation-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cron-fired window's Lambda task yields linked execution, task and invocation records.

    The Get* calls agree on WindowExecutionId, TaskExecutionId and InvocationId, typed LAMBDA."""
    ssm = ctx.client("ssm")
    lambda_client = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_lambda_role(ctx, iam)
    fn_arn = _create_lambda_function(ctx, lambda_client, role_arn, "lifecycle")

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0/1 * * * ? *)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # A targetless LAMBDA task needs no managed nodes and runs once per window fire.
    ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        TaskArn=fn_arn,
        TaskType="LAMBDA",
        Priority=1,
        TaskInvocationParameters={"Lambda": {"Payload": b'{"probe": "sim2real"}'}},
    )

    execution_id = _poll_until(
        lambda: _first_execution_id(ssm, window_id),
        lambda v: v is not None,
        timeout_s=360,
        interval_s=15,
    )
    if not execution_id:
        raise AssertionError(
            "maintenance window schedule never produced an execution within the timeout"
        )

    execution = _poll_until(
        lambda: ssm.get_maintenance_window_execution(WindowExecutionId=execution_id),
        lambda r: r.get("Status") in _TERMINAL_STATUSES and r.get("TaskIds"),
        timeout_s=180,
        interval_s=10,
    )
    assert execution["Status"] in _TERMINAL_STATUSES, (
        f"execution never reached a terminal state: {execution.get('Status')}"
    )
    assert execution["WindowExecutionId"] == execution_id
    task_ids = execution["TaskIds"]
    assert len(task_ids) == 1, f"expected exactly one registered task, got {task_ids}"
    task_id = task_ids[0]

    task = ssm.get_maintenance_window_execution_task(
        WindowExecutionId=execution_id, TaskId=task_id
    )
    assert task["WindowExecutionId"] == execution_id
    assert task["TaskExecutionId"] == task_id
    assert task["Type"] == "LAMBDA"
    assert task["TaskArn"] == fn_arn

    invocations = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=execution_id, TaskId=task_id
        ).get("WindowExecutionTaskInvocationIdentities", []),
        lambda v: len(v) >= 1,
        timeout_s=120,
        interval_s=10,
    )
    assert invocations, "no task invocation record was created for the executed Lambda task"
    assert invocations[0]["TaskExecutionId"] == task_id
    assert invocations[0]["WindowExecutionId"] == execution_id
    invocation_id = invocations[0]["InvocationId"]

    invocation = ssm.get_maintenance_window_execution_task_invocation(
        WindowExecutionId=execution_id, TaskId=task_id, InvocationId=invocation_id
    )
    assert invocation["WindowExecutionId"] == execution_id
    assert invocation["TaskExecutionId"] == task_id
    assert invocation["InvocationId"] == invocation_id
    assert invocation["TaskType"] == "LAMBDA"


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
    resp = ssm.describe_maintenance_window_executions(WindowId=window_id)
    execs = resp.get("WindowExecutions", [])
    return execs[0]["WindowExecutionId"] if execs else None


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_LAMBDA_BASIC_EXEC_POLICY_ARN = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
)


def _create_lambda_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-ssm-mw-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC_EXEC_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn=_LAMBDA_BASIC_EXEC_POLICY_ARN
        )
    )
    return role_arn


def _lambda_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_lambda_function(ctx, lambda_client, role_arn, name_suffix):
    # Maintenance window Lambda invocation via the SSM service-linked role requires the
    # function name to start with the literal prefix "SSM" (AmazonSSMMaintenanceWindowRole
    # scopes lambda:InvokeFunction to arn:aws:lambda:*:*:function:SSM*).
    fn_name = ctx.unique_name(f"SSMsim2real-mw-{name_suffix}-")
    code = _lambda_zip_bytes()
    last_err = None
    deadline = time.monotonic() + 90
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            fn_arn = lambda_client.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except lambda_client.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    if fn_arn is None:
        raise AssertionError(f"lambda function never became creatable: {last_err}")
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    return fn_arn


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
