"""callback-heartbeat-extends-deadline."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "callback-heartbeat-extends-deadline"
GROUP = "visibility-timeout-ttl"
SERVICES = ["lambda"]

_HANDLER_CODE = '''
import boto3
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig

_sqs = boto3.client("sqs")


@durable_execution
def lambda_handler(event, context: DurableContext):
    queue_url = event["queueUrl"]
    timeout_seconds = event.get("timeoutSeconds", 120)
    heartbeat_seconds = event.get("heartbeatTimeoutSeconds", 0)

    def _notify(callback_id, wait_for_callback_context):
        _sqs.send_message(QueueUrl=queue_url, MessageBody=callback_id)

    config_kwargs = {"timeout": Duration.from_seconds(timeout_seconds)}
    if heartbeat_seconds:
        config_kwargs["heartbeat_timeout"] = Duration.from_seconds(heartbeat_seconds)

    result = context.wait_for_callback(
        _notify, name="wait-for-signal", config=WaitForCallbackConfig(**config_kwargs)
    )
    if isinstance(result, bytes):
        result = result.decode("utf-8")
    return {"status": "completed", "result": result}
'''


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


# timing:real-time — workflow: 10 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A callback heartbeat extends the heartbeat deadline: a second heartbeat past the original
    deadline succeeds, and resolving the callback completes the execution with its result.
    """
    heartbeat_timeout_s = 10
    overall_timeout_s = 180

    queue_url, queue_arn = _create_destination_queue(ctx)
    fn = _create_durable_function(
        ctx, _HANDLER_CODE, execution_timeout=300, retention_days=1, queue_arn=queue_arn
    )
    exec_name = ctx.unique_name("sim2real-hbext-")
    arn = _invoke_durable(
        ctx,
        fn["name"],
        {
            "queueUrl": queue_url,
            "timeoutSeconds": overall_timeout_s,
            "heartbeatTimeoutSeconds": heartbeat_timeout_s,
        },
        exec_name,
    )

    # The CallbackId arrives over SQS from the handler's notify callback; the
    # CallbackStartedDetails history event does not reliably surface within a bounded window.
    callback_id = _receive_callback_id(ctx, queue_url, timeout_s=180)
    started_at = time.monotonic()
    if callback_id is None:
        raise _never_ready(
            f"durable execution {arn} never delivered a CallbackId over {queue_url} "
            "(the notify callback passed to wait_for_callback never fired within the poll window)",
        )

    lam = ctx.client("lambda")

    # First heartbeat: well inside the original heartbeat window.
    _hold_until_running(ctx, arn, started_at + heartbeat_timeout_s * 0.4)
    lam.send_durable_execution_callback_heartbeat(CallbackId=callback_id)

    # Second heartbeat: past the original deadline but inside the window the first one extended.
    _hold_until_running(ctx, arn, started_at + heartbeat_timeout_s * 1.3)
    resp = lam.send_durable_execution_callback_heartbeat(CallbackId=callback_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"heartbeat past the original deadline but inside the extended window was not accepted: {resp}"
    )

    lam.send_durable_execution_callback_success(
        CallbackId=callback_id, Result=b'{"approved": true, "reviewer": "sim2real"}'
    )
    status = _wait_for_execution_status(ctx, arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}, timeout_s=90)
    assert status == "SUCCEEDED", f"execution ended in unexpected status {status} after resolving callback"

    final = lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
    output = json.loads(final["Result"])
    assert output["status"] == "completed", f"unexpected handler output status: {output}"
    assert "approved" in output["result"], f"callback result payload not round-tripped: {output}"


def _hold_until_running(ctx, arn: str, target_monotonic: float, *, poll_interval_s: float = 2.0) -> None:
    """Hold until ``target_monotonic``, asserting the execution stays RUNNING throughout.

    A callback that times out too early is caught here rather than as an opaque heartbeat error.
    """
    lam = ctx.client("lambda")
    while True:
        remaining = target_monotonic - time.monotonic()
        if remaining <= 0:
            return
        status = lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False)["Status"]
        assert status == "RUNNING", (
            f"execution {arn} left RUNNING (status={status}) before the intended heartbeat "
            "instant -- the callback timed out before the heartbeat could extend it"
        )
        time.sleep(min(remaining, poll_interval_s))


_ROLE_TRUST_POLICY = json.dumps(
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

_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
)


def _zip_from_source(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_durable_execution_role(ctx, fn_name: str, queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-derole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The managed policy is not guaranteed to grant the SDK's checkpoint calls, without which the
    # execution never reaches wait_for_callback. sqs:SendMessage delivers the CallbackId.
    account = _account_id(ctx)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:CheckpointDurableExecution", "lambda:GetDurableExecutionState"],
                "Resource": f"arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}:*",
            },
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="durable-inline", PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for policy_arn in _MANAGED_POLICIES:
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


def _wait_function_active(ctx, fn_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {fn_name} entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {fn_name} did not become Active in {timeout_s}s (last state={state})")


def _create_destination_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-hbext-q-"),
        tags={"sim2real:check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return queue_url, queue_arn


def _receive_callback_id(ctx, queue_url: str, timeout_s: float = 180.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait_s = min(20, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s)
        messages = resp.get("Messages", [])
        if messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return messages[0]["Body"]
    # None lets the caller fail with more context via _never_ready.
    return None


def _create_durable_function(
    ctx, code: str, execution_timeout: int = 300, retention_days: int = 1, *, queue_arn: str
) -> dict:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-dfn-")
    role_arn = _create_durable_execution_role(ctx, fn_name, queue_arn)
    zip_bytes = _zip_from_source(code)

    resp = None
    last_err = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=60,
                DurableConfig={
                    "ExecutionTimeout": execution_timeout,
                    "RetentionPeriodInDays": retention_days,
                },
                Tags={"sim2real:check": CHECK},
            )
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create durable function, last error: {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_function_active(ctx, fn_name)
    return {"name": fn_name, "arn": resp["FunctionArn"]}


def _wait_for_durable_execution_arn(ctx, fn_name: str, execution_name: str, timeout_s: float = 30.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = lam.list_durable_executions_by_function(
            FunctionName=fn_name, DurableExecutionName=execution_name
        )
        execs = resp.get("DurableExecutions", [])
        if execs:
            return execs[0]["DurableExecutionArn"]
        time.sleep(2)
    raise AssertionError(f"durable execution named {execution_name} not found in {timeout_s}s")


def _invoke_durable(ctx, fn_name: str, payload: dict, execution_name: str) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    assert resp["StatusCode"] == 202, f"expected async invoke StatusCode 202, got {resp['StatusCode']}"
    arn = resp.get("DurableExecutionArn")
    if not arn:
        arn = _wait_for_durable_execution_arn(ctx, fn_name, execution_name)
    return arn


def _wait_for_execution_status(ctx, arn: str, target_statuses: set, timeout_s: float = 120.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False)
        status = resp["Status"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"execution {arn} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the function's log group; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
