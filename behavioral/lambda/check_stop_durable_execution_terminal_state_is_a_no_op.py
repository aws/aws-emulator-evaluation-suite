"""stop-durable-execution-terminal-state-is-a-no-op."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-durable-execution-terminal-state-is-a-no-op"
GROUP = "state-machine"
SERVICES = ["lambda"]

_QUICK_HANDLER = '''
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)


@durable_step
def do_step(step_context, value):
    return {"stepped": value}


@durable_execution
def lambda_handler(event, context: DurableContext):
    return {"result": context.step(do_step(event.get("value", "x")))}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """StopDurableExecution on a SUCCEEDED execution is accepted without error, reports SUCCEEDED, and
    leaves the execution SUCCEEDED rather than STOPPED."""
    lam = ctx.client("lambda")
    role_arn = _create_durable_role(ctx)
    name = ctx.unique_name("sim2real-durstopneg-")
    _create_durable_function(
        ctx,
        name=name,
        role_arn=role_arn,
        handler_source=_QUICK_HANDLER,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )

    arn = _invoke_durable(ctx, function_name=name, payload={}, execution_name=ctx.unique_name("term-"))

    # Immediately after an async (Event) Invoke, GetDurableExecution can briefly answer
    # ResourceNotFoundException before the execution record propagates -- a genuine
    # eventual-consistency window, not a rejection. Treat it as "not yet visible" rather
    # than letting it abort the poll early.
    final = _poll_until(
        lambda: _get_execution_tolerant(lam, arn),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
        timeout_s=45.0,
        interval_s=2.0,
    )
    assert final["Status"] == "SUCCEEDED", f"expected the quick execution to finish SUCCEEDED, got {final['Status']}"

    # Real AWS accepts StopDurableExecution against an already-terminal execution as
    # a no-op (HTTP 200, no exception) instead of rejecting it with
    # InvalidParameterValueException. The invariant that matters -- and that we assert
    # here -- is that this no-op call must NOT mutate the already-recorded terminal
    # status (it must not, for instance, flip a SUCCEEDED execution to STOPPED).
    stop_resp = lam.stop_durable_execution(DurableExecutionArn=arn)
    reported_status = stop_resp.get("Status")
    if reported_status is not None:
        assert reported_status == "SUCCEEDED", (
            f"expected StopDurableExecution against an already-SUCCEEDED execution to report "
            f"the existing terminal status rather than transition it, got {reported_status!r}"
        )

    # The execution must remain in its terminal state; the no-op Stop must not mutate it.
    after = lam.get_durable_execution(DurableExecutionArn=arn)
    assert after["Status"] == "SUCCEEDED", f"terminal status must be preserved, got {after['Status']}"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _get_execution_tolerant(lam, arn: str) -> dict:
    from botocore.exceptions import ClientError

    try:
        return lam.get_durable_execution(DurableExecutionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return {"Status": "PENDING"}
        raise


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
