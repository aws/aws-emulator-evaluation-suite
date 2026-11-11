"""get-durable-execution-state-invalid-checkpoint-token-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-durable-execution-state-invalid-checkpoint-token-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]

_HANDLER_SOURCE = """
from aws_durable_execution_sdk_python import DurableContext, durable_execution, durable_step


@durable_step
def _identity(step_context, value):
    return {"value": value}


@durable_execution
def handler(event, context: DurableContext):
    return context.step(_identity(event.get("value", "x")))
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDurableExecutionState rejects a well-formed but never-issued CheckpointToken with
    InvalidParameterValueException instead of returning state for it."""
    lam = ctx.client("lambda")
    if not hasattr(lam, "get_durable_execution_state"):
        raise AssertionError("boto3 lambda client does not support GetDurableExecutionState")

    role_arn = _create_durable_role(ctx)
    fn_name, version = _create_durable_function(ctx, role_arn, _HANDLER_SOURCE)

    resp = lam.invoke(FunctionName=fn_name, Qualifier=version, Payload=json.dumps({"value": "y"}).encode())
    arn = resp["DurableExecutionArn"]

    _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT"),
        timeout_s=30,
        interval_s=2,
    )

    # Well-formed base64-shaped token (matches the API's syntactic pattern) but not one
    # ever issued by the runtime for this execution.
    forged_token = "Zm9yZ2VkLXRva2Vu"

    code, message = _error_code_and_message(
        lambda: lam.get_durable_execution_state(DurableExecutionArn=arn, CheckpointToken=forged_token)
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    # The exact message names the checkpoint token as the thing rejected, so this cannot be
    # conflated with a differently-shaped 400 that also lands on InvalidParameterValueException.
    expected_message = "Invalid checkpoint token"
    assert message == expected_message, (
        f"expected the rejection message {expected_message!r}, got: {message!r}"
    )


def _error_code_and_message(fn):
    try:
        fn()
        raise AssertionError("expected the call to be rejected, but it succeeded")
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_durable_role(ctx: Any) -> str:
    import json as _json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-durrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"

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
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_function_with_retry(ctx: Any, **kwargs: Any) -> dict:
    lam = ctx.client("lambda")
    last_err: Exception | None = None
    for _ in range(10):
        try:
            return lam.create_function(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    assert last_err is not None
    raise last_err


def _wait_active(ctx: Any, fn_name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function {fn_name} entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {fn_name} did not become Active within {timeout_s}s")


def _create_durable_function(
    ctx: Any,
    role_arn: str,
    handler_source: str,
    execution_timeout: int = 600,
    retention_days: int = 1,
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-durfn-")
    _create_function_with_retry(
        ctx,
        FunctionName=fn_name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="handler.handler",
        Code={"ZipFile": _zip_from_source("handler.py", handler_source)},
        Timeout=60,
        DurableConfig={"ExecutionTimeout": execution_timeout, "RetentionPeriodInDays": retention_days},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_active(ctx, fn_name)
    version = lam.publish_version(FunctionName=fn_name)["Version"]
    return fn_name, version


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on first invocation. Late log delivery can recreate it,
    so it must stay absent across two reads 5 s apart; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
