"""describe-maintenance-window-execution-tasks-lists-all."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-maintenance-window-execution-tasks-lists-all"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "TIMED_OUT", "CANCELLED"}


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """DescribeMaintenanceWindowExecutionTasks lists every task invoked during a given
    execution id -- registering two distinct targetless Lambda tasks on one window must
    surface BOTH task-execution records (matched by TaskArn), not just one."""
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
        Tags=[{"Key": "sim2real-mw-execution-tasks", "Value": "1"}],
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
        reason="the maintenance window schedule to produce an execution",
    )

    execution = _poll_until(
        lambda: ssm.get_maintenance_window_execution(WindowExecutionId=execution_id),
        lambda r: r.get("Status") in _TERMINAL_STATUSES and len(r.get("TaskIds", [])) >= 2,
        timeout_s=180,
        interval_s=10,
        reason="the execution to reach a terminal status with both tasks registered",
    )
    assert execution["Status"] in _TERMINAL_STATUSES, (
        f"expected a terminal status in {_TERMINAL_STATUSES}, got {execution['Status']!r}"
    )
    task_ids = set(execution["TaskIds"])
    assert len(task_ids) == 2, f"expected two registered tasks, got {execution['TaskIds']}"

    listed = ssm.describe_maintenance_window_execution_tasks(WindowExecutionId=execution_id)
    identities = listed["WindowExecutionTaskIdentities"]

    listed_task_ids = {i["TaskExecutionId"] for i in identities}
    assert listed_task_ids == task_ids, (
        f"DescribeMaintenanceWindowExecutionTasks did not list every task: "
        f"listed={listed_task_ids} expected={task_ids}"
    )

    listed_task_arns = {i["TaskArn"] for i in identities}
    assert listed_task_arns == {fn_arn_a, fn_arn_b}, (
        f"expected the two registered task ARNs {{fn_arn_a, fn_arn_b}}, "
        f"got {listed_task_arns}"
    )

    # Cross-check each listed identity against the authoritative single-task Get call.
    for identity in identities:
        got = ssm.get_maintenance_window_execution_task(
            WindowExecutionId=execution_id, TaskId=identity["TaskExecutionId"]
        )
        assert got["TaskArn"] == identity["TaskArn"], (
            f"GetMaintenanceWindowExecutionTask TaskArn {got['TaskArn']!r} disagrees "
            f"with the listed identity's {identity['TaskArn']!r}"
        )
        assert got["TaskExecutionId"] == identity["TaskExecutionId"], (
            f"GetMaintenanceWindowExecutionTask TaskExecutionId {got['TaskExecutionId']!r} "
            f"disagrees with the listed identity's {identity['TaskExecutionId']!r}"
        )
        assert got["Type"] == "LAMBDA", f"expected task type LAMBDA, got {got['Type']!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {reason}; last observed: {last!r}"
    )


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
        Tags=[{"Key": "sim2real-mw-execution-tasks", "Value": "1"}],
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
                Tags={"sim2real-mw-execution-tasks": "1"},
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
