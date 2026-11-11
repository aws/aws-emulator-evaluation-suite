"""durable-execution-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-execution-lifecycle"
GROUP = "state-machine"
SERVICES = ["lambda"]

_LIFECYCLE_HANDLER = '''
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
    step_result = context.step(do_step(event.get("value", "x")))
    context.wait(Duration.from_seconds(int(event.get("wait_seconds", 10))))
    return {"result": step_result, "done": True}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A durable execution goes from RUNNING to SUCCEEDED with checkpoint history when it completes,
    and from RUNNING to STOPPED when StopDurableExecution is called while it runs."""
    lam = ctx.client("lambda")
    role_arn = _create_durable_role(ctx)
    name = ctx.unique_name("sim2real-durlife-")
    _create_durable_function(
        ctx,
        name=name,
        role_arn=role_arn,
        handler_source=_LIFECYCLE_HANDLER,
        durable_config={"ExecutionTimeout": 600, "RetentionPeriodInDays": 1},
    )

    # --- flow 1: RUNNING -> checkpointed -> SUCCEEDED ---
    arn_ok = _invoke_durable(ctx, function_name=name, payload={"wait_seconds": 8}, execution_name=ctx.unique_name("ok-"))

    # Invoke() hands back a DurableExecutionArn before the execution is visible to
    # GetDurableExecution: the very first read can 404 with ResourceNotFoundException even
    # though the ARN is the correct, eventual one. Only the FIRST read on a freshly-invoked
    # ARN needs to ride that out; once it has been seen once, later reads never regress to
    # not-found.
    seen = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn_ok),
        lambda e: e["Status"] in ("RUNNING", "SUCCEEDED"),
        timeout_s=30.0,
        interval_s=2.0,
        tolerate_not_found=True,
    )
    assert seen["Status"] in ("RUNNING", "SUCCEEDED"), seen["Status"]

    history = _poll_until(
        lambda: lam.get_durable_execution_history(DurableExecutionArn=arn_ok)["Events"],
        lambda evs: len(evs) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert len(history) >= 1, "expected the SDK's automatic checkpointing to leave a history event"

    final = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn_ok),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
        timeout_s=45.0,
        interval_s=3.0,
    )
    assert final["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['Status']}: {final.get('Error')}"

    # --- flow 2: RUNNING -> STOPPED ---
    arn_stop = _invoke_durable(
        ctx, function_name=name, payload={"wait_seconds": 120}, execution_name=ctx.unique_name("stop-")
    )

    _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn_stop),
        lambda e: e["Status"] == "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
        tolerate_not_found=True,
    )
    lam.stop_durable_execution(DurableExecutionArn=arn_stop)
    stopped = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn_stop),
        lambda e: e["Status"] in ("STOPPED", "SUCCEEDED", "FAILED", "TIMED_OUT"),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "STOPPED", f"expected STOPPED, got {stopped['Status']}"


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(
    probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0, tolerate_not_found: bool = False
):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if tolerate_not_found and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(interval_s)
                continue
            raise
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
