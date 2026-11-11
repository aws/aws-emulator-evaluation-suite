"""sfn-startexecution-input-passthrough-to-lambda-task."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-startexecution-input-passthrough-to-lambda-task"
GROUP = "data-format"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The JSON input given to StartExecution flows unchanged into the first (and only) Task
    state's Lambda invocation payload, and the Lambda's raw return value becomes the
    execution's final output verbatim."""
    lambda_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        managed_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    echo_code = "def handler(event, context):\n    return event\n"
    function_arn = _create_function(ctx, lambda_role_arn, echo_code)

    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}],
        },
    )
    sm_arn = _create_state_machine(
        ctx,
        sfn_role_arn,
        {
            "StartAt": "Invoke",
            "States": {
                "Invoke": {
                    "Type": "Task",
                    "Resource": function_arn,
                    "Retry": [
                        {
                            "ErrorEquals": ["States.ALL"],
                            "IntervalSeconds": 3,
                            "MaxAttempts": 6,
                            "BackoffRate": 2.0,
                        }
                    ],
                    "End": True,
                }
            },
        },
    )

    test_input = {"key": "value123", "nested": {"a": 1, "b": [1, 2, 3]}, "flag": True}
    sfn = ctx.client("stepfunctions")
    exec_name = ctx.unique_name("sim2real-exec-")
    start = _retry_until(
        lambda: sfn.start_execution(
            stateMachineArn=sm_arn, name=exec_name, input=json.dumps(test_input)
        ),
        retryable_codes=("AccessDeniedException",),
    )
    execution = _wait_for_terminal(ctx, start["executionArn"], timeout_s=60)
    assert execution["status"] == "SUCCEEDED", (
        f"execution must run to completion: expected status SUCCEEDED, got "
        f"{execution['status']!r} (execution {start['executionArn']!r})"
    )
    assert json.loads(execution["input"]) == test_input, (
        f"DescribeExecution's own recorded input must echo exactly what StartExecution was "
        f"given: expected {test_input!r}, got {json.loads(execution['input'])!r}"
    )
    assert json.loads(execution["output"]) == test_input, (
        "the Lambda Task's echoed return value did not match the exact StartExecution input, "
        "meaning the input was mutated somewhere in the pass-through"
    )

    # DescribeExecution's own input/output rollup would look identical to test_input even if
    # the engine never actually routed through the Lambda task (e.g. a stub that just copies
    # StartExecution's input straight to the execution's output). GetExecutionHistory is an
    # independent read of the Task state's own scheduled/succeeded events, which is where the
    # pass-through the docstring claims actually has to be observed.
    history = sfn.get_execution_history(executionArn=start["executionArn"], includeExecutionData=True)
    events = history["events"]
    scheduled = next(e for e in events if e["type"] == "LambdaFunctionScheduled")
    succeeded = next(e for e in events if e["type"] == "LambdaFunctionSucceeded")
    scheduled_input = json.loads(scheduled["lambdaFunctionScheduledEventDetails"]["input"])
    succeeded_output = json.loads(succeeded["lambdaFunctionSucceededEventDetails"]["output"])
    assert scheduled_input == test_input, (
        f"the Lambda invocation payload recorded in the execution history must be exactly the "
        f"StartExecution input, independent of the execution's own output rollup: expected "
        f"{test_input!r}, got {scheduled_input!r}"
    )
    assert succeeded_output == test_input, (
        f"the Lambda invocation's own recorded return value in the execution history must be "
        f"exactly the input it was given: expected {test_input!r}, got {succeeded_output!r}"
    )


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(
    ctx,
    principal: str,
    inline_policy: dict[str, Any] | None = None,
    managed_arns: list[str] | None = None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for arn in managed_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_until(fn, retryable_codes: tuple[str, ...], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retryable_codes:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded after retrying for role propagation: {last_err}")


def _create_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _lambda_zip(code)
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    resp = _retry_until(
        lambda: lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=timeout,
            Tags={"sim2real": CHECK},
        ),
        retryable_codes=("InvalidParameterValueException",),
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = _retry_until(
        lambda: sfn.create_state_machine(
            name=name,
            definition=json.dumps(definition),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        ),
        retryable_codes=("AccessDeniedException",),
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_for_terminal(ctx, execution_arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(3)
    raise AssertionError("execution did not reach a terminal state in time")


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
