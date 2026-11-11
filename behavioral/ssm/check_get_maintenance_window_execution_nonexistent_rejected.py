"""get-maintenance-window-execution-nonexistent-rejected."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-maintenance-window-execution-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """GetMaintenanceWindowExecution rejects an unknown execution id with DoesNotExistException.

    The same operation on a real execution produced by the window's schedule succeeds, so the
    rejection is specific to the unknown id."""
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")

    role_arn = _create_lambda_role(ctx, iam)
    fn_arn = _create_lambda_function(ctx, lambda_client, role_arn)

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0/1 * * * ? *)",
        ScheduleTimezone="UTC",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    # A targetless LAMBDA task is enough to make the window's schedule produce a real
    # execution -- no managed EC2 node required.
    ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        TaskArn=fn_arn,
        TaskType="LAMBDA",
        Priority=1,
        TaskInvocationParameters={"Lambda": {"Payload": b'{"probe": "sim2real"}'}},
    )

    real_execution_id = _poll_until(
        lambda: _first_execution_id(ssm, window_id),
        lambda v: v is not None,
        timeout_s=200.0,
        interval_s=10.0,
    )
    assert real_execution_id is not None, (
        f"cron schedule never produced a live WindowExecution for {window_id} "
        "within the poll window"
    )

    control = ssm.get_maintenance_window_execution(WindowExecutionId=real_execution_id)
    assert control["WindowExecutionId"] == real_execution_id, control

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
    """Return the botocore Error dict fn() raises; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


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
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_LAMBDA_BASIC_EXEC_POLICY_ARN)
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


def _create_lambda_function(ctx, lambda_client, role_arn):
    # Maintenance window Lambda invocation via the SSM service-linked role requires the
    # function name to start with the literal prefix "SSM" (AmazonSSMMaintenanceWindowRole
    # scopes lambda:InvokeFunction to arn:aws:lambda:*:*:function:SSM*).
    fn_name = ctx.unique_name("SSMsim2real-mw-")
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
