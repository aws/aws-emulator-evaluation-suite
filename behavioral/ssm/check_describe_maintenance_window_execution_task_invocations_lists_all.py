"""describe-maintenance-window-execution-task-invocations-lists-all."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-maintenance-window-execution-task-invocations-lists-all"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED"}


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """DescribeMaintenanceWindowExecutionTaskInvocations lists exactly a task's own invocations:
    with two targetless Lambda tasks in one execution, neither list contains the other's."""
    ssm = ctx.client("ssm")
    lambda_client = ctx.client("lambda")
    iam = ctx.client("iam")

    role_arn = _create_lambda_role(ctx, iam)
    fn_arn_a = _create_lambda_function(ctx, lambda_client, role_arn, "taska")
    fn_arn_b = _create_lambda_function(ctx, lambda_client, role_arn, "taskb")

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0/1 * * * ? *)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    for fn_arn in (fn_arn_a, fn_arn_b):
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
        lambda r: r.get("Status") in _TERMINAL_STATUSES and len(r.get("TaskIds", [])) >= 2,
        timeout_s=180,
        interval_s=10,
    )
    assert execution["Status"] in _TERMINAL_STATUSES, (
        f"execution never reached a terminal state: {execution.get('Status')}"
    )
    assert len(execution["TaskIds"]) == 2, (
        f"expected exactly 2 registered tasks in this execution, got {execution['TaskIds']}"
    )

    listed = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=execution_id)
    identities = listed["WindowExecutionTaskIdentities"]
    task_id_by_arn = {i["TaskArn"]: i["TaskExecutionId"] for i in identities}
    assert set(task_id_by_arn) == {fn_arn_a, fn_arn_b}, (
        f"expected task ARNs {{fn_arn_a, fn_arn_b}}, got {set(task_id_by_arn)}"
    )
    task_id_a = task_id_by_arn[fn_arn_a]
    task_id_b = task_id_by_arn[fn_arn_b]

    invocations_a = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=execution_id, TaskId=task_id_a
        ).get("WindowExecutionTaskInvocationIdentities", []),
        lambda v: len(v) >= 1,
        timeout_s=120,
        interval_s=10,
    )
    invocations_b = _poll_until(
        lambda: ssm.describe_maintenance_window_execution_task_invocations(
            WindowExecutionId=execution_id, TaskId=task_id_b
        ).get("WindowExecutionTaskInvocationIdentities", []),
        lambda v: len(v) >= 1,
        timeout_s=120,
        interval_s=10,
    )
    assert invocations_a and invocations_b, "expected an invocation record for both tasks"

    # Completeness: exactly the invocation(s) belonging to each task -- no more, no less.
    assert len(invocations_a) == 1, f"expected exactly 1 invocation for task A, got {invocations_a}"
    assert len(invocations_b) == 1, f"expected exactly 1 invocation for task B, got {invocations_b}"

    # Scoping: task A's invocation list must not contain task B's invocation, and vice versa.
    assert invocations_a[0]["TaskExecutionId"] == task_id_a, (
        f"expected TaskExecutionId {task_id_a} in task A's invocation, got {invocations_a[0]['TaskExecutionId']}"
    )
    assert invocations_b[0]["TaskExecutionId"] == task_id_b, (
        f"expected TaskExecutionId {task_id_b} in task B's invocation, got {invocations_b[0]['TaskExecutionId']}"
    )
    assert invocations_a[0]["InvocationId"] != invocations_b[0]["InvocationId"], (
        "task A and task B invocations must not share an InvocationId"
    )
    invocation_id_a = invocations_a[0]["InvocationId"]
    invocation_id_b = invocations_b[0]["InvocationId"]
    assert invocation_id_a not in {inv["InvocationId"] for inv in invocations_b}, (
        f"task A's invocation {invocation_id_a} leaked into task B's invocation list"
    )
    assert invocation_id_b not in {inv["InvocationId"] for inv in invocations_a}, (
        f"task B's invocation {invocation_id_b} leaked into task A's invocation list"
    )

    # Cross-check each against the authoritative single-invocation Get call.
    got_a = ssm.get_maintenance_window_execution_task_invocation(
        WindowExecutionId=execution_id, TaskId=task_id_a, InvocationId=invocation_id_a
    )
    got_b = ssm.get_maintenance_window_execution_task_invocation(
        WindowExecutionId=execution_id, TaskId=task_id_b, InvocationId=invocation_id_b
    )
    assert got_a["TaskExecutionId"] == task_id_a, (
        f"Get for task A returned TaskExecutionId {got_a['TaskExecutionId']}, expected {task_id_a}"
    )
    assert got_b["TaskExecutionId"] == task_id_b, (
        f"Get for task B returned TaskExecutionId {got_b['TaskExecutionId']}, expected {task_id_b}"
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
        RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY
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
