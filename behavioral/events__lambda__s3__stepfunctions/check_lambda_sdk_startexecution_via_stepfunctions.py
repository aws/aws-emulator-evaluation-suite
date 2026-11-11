"""lambda-sdk-startexecution-via-stepfunctions."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-startexecution-via-stepfunctions"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]

_HANDLER_SRC = """
import json, os, boto3

def handler(event, context):
    sfn = boto3.client('stepfunctions')
    resp = sfn.start_execution(
        stateMachineArn=os.environ['SM_ARN'],
        name=event.get('name'),
        input=json.dumps(event.get('input', {})),
    )
    return {'executionArn': resp['executionArn']}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler that calls stepfunctions.start_execution actually starts a new,
    observable execution (visible via DescribeExecution with the right input), not just a
    call that returns 200 inside the sandbox."""
    sfn = ctx.client("stepfunctions")

    sm_role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, sm_role_arn, _PASS_DEFINITION)

    lambda_role_arn = _create_lambda_role(
        ctx,
        inline_policies={
            "start-execution": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}
                ],
            }
        },
    )
    fn_name, _ = _create_lambda(ctx, lambda_role_arn, _HANDLER_SRC, env={"SM_ARN": sm_arn})

    exec_name = ctx.unique_name("sim2real-exec-")
    result = _invoke_lambda(ctx, fn_name, {"name": exec_name, "input": {"hello": "world"}})
    execution_arn = result["executionArn"]
    assert execution_arn.endswith(exec_name), (
        f"executionArn returned to the Lambda's boto3 call must carry the requested "
        f"execution name: expected suffix {exec_name!r}, got {execution_arn!r}"
    )

    desc = sfn.describe_execution(executionArn=execution_arn)
    assert desc["stateMachineArn"] == sm_arn, (
        f"execution started from inside the Lambda must belong to the state machine it "
        f"targeted: expected {sm_arn!r}, got {desc['stateMachineArn']!r}"
    )
    assert json.loads(desc["input"]) == {"hello": "world"}, (
        f"execution input observed via an independent DescribeExecution must match what the "
        f"Lambda passed: expected {{'hello': 'world'}}, got {json.loads(desc['input'])!r}"
    )

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT"),
        timeout_s=30,
        interval_s=1.5,
    )
    assert final["status"] == "SUCCEEDED", (
        f"execution started via the Lambda's stepfunctions.start_execution call must run to "
        f"completion: expected status SUCCEEDED, got {final['status']!r} "
        f"(execution {execution_arn!r})"
    )


_PASS_DEFINITION = {
    "Comment": "sim2real pass-through",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "End": True}},
}


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                Tags={"sim2real": CHECK},
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
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            arn = resp["stateMachineArn"]
            break
        except ClientError as e:  # role not yet assumable
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
