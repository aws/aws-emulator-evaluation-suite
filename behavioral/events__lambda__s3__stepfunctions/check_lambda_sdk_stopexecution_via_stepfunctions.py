"""lambda-sdk-stopexecution-via-stepfunctions."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-stopexecution-via-stepfunctions"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]

_HANDLER_SRC = """
import boto3

def handler(event, context):
    sfn = boto3.client('stepfunctions')
    sfn.stop_execution(executionArn=event['executionArn'])
    return {'stopped': True}
"""

_WAIT_DEFINITION = {
    "Comment": "sim2real long wait, stopped externally",
    "StartAt": "WaitState",
    "States": {"WaitState": {"Type": "Wait", "Seconds": 300, "End": True}},
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler that calls stepfunctions.stop_execution transitions a genuinely RUNNING
    execution to ABORTED (polled to the real terminal state, not just a 200 from the API call)."""
    sfn = ctx.client("stepfunctions")

    sm_role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sm_role_arn, _WAIT_DEFINITION)

    exec_name = ctx.unique_name("sim2real-exec-")
    started = sfn.start_execution(stateMachineArn=sm_arn, name=exec_name)
    execution_arn = started["executionArn"]
    ctx.on_cleanup(
        lambda: sfn.stop_execution(executionArn=execution_arn)
        if sfn.describe_execution(executionArn=execution_arn)["status"] == "RUNNING"
        else None
    )

    running = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] == "RUNNING",
        timeout_s=20,
        interval_s=1,
    )
    assert running["status"] == "RUNNING", f"expected execution RUNNING before invoking lambda, got {running['status']!r}"

    execution_resource = sm_arn.replace(":stateMachine:", ":execution:") + ":*"
    lambda_role_arn = _create_lambda_role(
        ctx,
        inline_policies={
            "stop-execution": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:StopExecution", "Resource": execution_resource}
                ],
            }
        },
    )
    fn_name, _ = _create_lambda(ctx, lambda_role_arn, _HANDLER_SRC)

    result = _invoke_lambda(ctx, fn_name, {"executionArn": execution_arn})
    assert result["stopped"] is True, f"expected lambda handler to report stopped=True, got {result!r}"

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30,
        interval_s=1.5,
    )
    assert final["status"] == "ABORTED", f"expected execution ABORTED after lambda's stop_execution call, got {final['status']!r}"
    assert "stopDate" in final, f"expected a stopDate on the aborted execution, got keys {sorted(final)!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_policies: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_arn


def _create_sfn_role(ctx, inline_policies: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-srole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_arn


def _create_lambda(ctx, role_arn: str, handler_src: str, env: dict[str, str] | None = None, timeout: int = 30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    code = _zip_code(handler_src)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    return name, resp["FunctionArn"]


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = None
    last_err = None
    for _ in range(12):
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            arn = resp["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = e
            time.sleep(3)
    if arn is None:
        raise last_err
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _invoke_lambda(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload).encode("utf-8"), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {body}")
    return body


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
