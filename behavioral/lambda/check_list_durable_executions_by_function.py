"""list-durable-executions-by-function."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-durable-executions-by-function"
GROUP = "state-machine"
SERVICES = ["lambda"]

_QUICK_HANDLER = '''
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)
from aws_durable_execution_sdk_python.config import Duration


@durable_step
def do_step(step_context, value):
    return {"stepped": value}


@durable_execution
def lambda_handler(event, context: DurableContext):
    result = context.step(do_step(event.get("value", "x")))
    context.wait(Duration.from_seconds(int(event.get("wait_seconds", 8))))
    return {"result": result}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """ListDurableExecutionsByFunction lists two just-started durable executions as RUNNING with their
    function ARN, and later lists both as SUCCEEDED once their wait and final checkpoint complete."""
    lam = ctx.client("lambda")
    role_arn = _create_durable_role(ctx)
    name = ctx.unique_name("sim2real-durlist-")
    _create_durable_function(
        ctx,
        name=name,
        role_arn=role_arn,
        handler_source=_QUICK_HANDLER,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )

    arn_a = _invoke_durable(ctx, function_name=name, payload={"wait_seconds": 10}, execution_name=ctx.unique_name("a-"))
    arn_b = _invoke_durable(ctx, function_name=name, payload={"wait_seconds": 10}, execution_name=ctx.unique_name("b-"))

    listed = _poll_until(
        lambda: {e["DurableExecutionArn"]: e for e in lam.list_durable_executions_by_function(FunctionName=name)["DurableExecutions"]},
        lambda by: arn_a in by and arn_b in by,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert listed[arn_a]["Status"] == "RUNNING", f"expected RUNNING, got {listed[arn_a]['Status']!r}"
    assert listed[arn_b]["Status"] == "RUNNING", f"expected RUNNING, got {listed[arn_b]['Status']!r}"
    assert listed[arn_a]["FunctionArn"].startswith("arn:"), (
        f"expected FunctionArn to start with 'arn:', got {listed[arn_a]['FunctionArn']!r}"
    )

    settled = _poll_until(
        lambda: {e["DurableExecutionArn"]: e for e in lam.list_durable_executions_by_function(FunctionName=name)["DurableExecutions"]},
        lambda by: by.get(arn_a, {}).get("Status") == "SUCCEEDED" and by.get(arn_b, {}).get("Status") == "SUCCEEDED",
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert settled[arn_a]["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {settled[arn_a]['Status']!r}"
    assert settled[arn_b]["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {settled[arn_b]['Status']!r}"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_durable_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-durable-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_durable_function(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    handler_source: str,
    durable_config: dict,
    timeout_s: float = 120.0,
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    if not hasattr(lam, "get_durable_execution"):
        raise AssertionError("installed botocore/client does not expose the Lambda durable-execution APIs")
    create_fn_shape = lam._service_model.operation_model("CreateFunction").input_shape
    if "DurableConfig" not in create_fn_shape.members:
        raise AssertionError("installed botocore/client does not model CreateFunction's DurableConfig parameter")

    zip_bytes = _zip_from_source("lambda_function.py", handler_source)
    deadline = time.monotonic() + timeout_s
    resp = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=120,
                MemorySize=256,
                DurableConfig=durable_config,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            msg = str(exc)
            if code == "InvalidParameterValueException" and "role" in msg.lower():
                time.sleep(3)
                continue
            raise AssertionError(f"durable functions are not available in this environment: {exc}") from exc
    if resp is None:
        raise AssertionError(f"could not create durable function after retries: {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"durable function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


def _invoke_durable(ctx: Any, *, function_name: str, payload: dict, execution_name: str) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    arn = resp.get("DurableExecutionArn")
    if arn:
        return arn
    return _poll_until(
        lambda: _find_execution_arn(lam, function_name, execution_name),
        lambda a: a is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )


def _find_execution_arn(lam, function_name: str, execution_name: str):
    execs = lam.list_durable_executions_by_function(FunctionName=function_name)["DurableExecutions"]
    for e in execs:
        if e["DurableExecutionName"] == execution_name:
            return e["DurableExecutionArn"]
    return None


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
