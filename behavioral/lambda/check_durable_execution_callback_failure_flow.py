"""durable-execution-callback-failure-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-execution-callback-failure-flow"
GROUP = "state-machine"
SERVICES = ["lambda"]

# GetDurableExecutionHistory may not surface the CallbackStartedDetails event promptly, even after
# the execution has reached the checkpoint. So the handler's notify step sends the CallbackId to an
# SQS queue instead of relying on the history API to surface it.
_CALLBACK_HANDLER = '''
import boto3
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig

_sqs = boto3.client("sqs")


@durable_execution
def lambda_handler(event, context: DurableContext):
    queue_url = event["queue_url"]

    def _notify(callback_id, wait_for_callback_context):
        _sqs.send_message(QueueUrl=queue_url, MessageBody=callback_id)

    approval = context.wait_for_callback(
        _notify,
        name="approval-callback",
        config=WaitForCallbackConfig(timeout=Duration.from_seconds(int(event.get("timeout_seconds", 300)))),
    )
    return {"approval": approval}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Sending a failure callback for a waiting durable execution's task token
    transitions the execution to FAILED, and the supplied error surfaces on the
    execution's Error field instead of the callback silently succeeding."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-durcbfail-")
    role_arn = _create_durable_role(ctx)
    _create_durable_function(
        ctx,
        name=name,
        role_arn=role_arn,
        handler_source=_CALLBACK_HANDLER,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )

    queue_url = _create_destination_queue(ctx)

    arn = _invoke_durable(
        ctx,
        function_name=name,
        payload={"timeout_seconds": 300, "queue_url": queue_url},
        execution_name=ctx.unique_name("cb-fail-"),
    )

    callback_id = _receive_callback_id(ctx, queue_url)
    if callback_id is None:
        raise AssertionError(
            "durable execution never reached the wait_for_callback checkpoint "
            "(the notify callback never delivered a CallbackId to the destination queue); "
            "cannot exercise the callback-failure effect without a callback to fail",
        )

    lam.send_durable_execution_callback_failure(
        CallbackId=callback_id,
        Error={"ErrorMessage": "rejected by approver", "ErrorType": "ApprovalRejected"},
    )

    final = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
        timeout_s=45.0,
        interval_s=2.0,
    )
    assert final["Status"] == "FAILED", f"expected FAILED, got {final['Status']}"

    error = final.get("Error") or {}
    error_blob = json.dumps(error)
    assert "rejected by approver" in error_blob, f"expected the callback's error to surface, got {error_blob}"


# ===== helpers (self-contained) =====


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


def _create_destination_queue(ctx: Any) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-durcbfail-dest-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _receive_callback_id(ctx: Any, queue_url: str, timeout_s: float = 180.0):
    # Real AWS can take well over a minute to cold-start the durable-execution SDK runtime and
    # checkpoint through wait_for_callback. It's also possible for the execution to never reach
    # that checkpoint at all (e.g. it settles into a terminal state first) -- polling forever in
    # that case would just be waiting out the clock, so this returns None on timeout instead of
    # raising, and the caller decides whether that's a reason to fail.
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        messages = resp.get("Messages")
        if messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return messages[0]["Body"]
    return None


_DURABLE_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)


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

    # Attach the AWS managed durable-execution policy, which grants every action the SDK runtime
    # needs to checkpoint and progress past wait_for_callback, instead of re-deriving the action list.
    for policy_arn in _DURABLE_MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The handler's own notify() side-channels the CallbackId out to a destination SQS queue
    # (see _CALLBACK_HANDLER) rather than trusting GetDurableExecutionHistory to surface it.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="durable-inline", PolicyDocument=json.dumps(policy_doc))

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for policy_arn in _DURABLE_MANAGED_POLICIES:
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
