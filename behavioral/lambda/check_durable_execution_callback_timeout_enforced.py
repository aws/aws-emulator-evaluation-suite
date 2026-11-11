"""durable-execution-callback-timeout-enforced."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "durable-execution-callback-timeout-enforced"
GROUP = 'durable_execution'
SERVICES = ['lambda']

DURABLE_RUNTIME = "python3.13"
DURABLE_HANDLER_ENTRY = "lambda_function.lambda_handler"

DURABLE_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

# A durable function that checkpoints one step, then suspends on wait_for_callback, surfacing the
# CallbackId to the outside world by sending it to a caller-supplied SQS queue URL. Controlled by
# the invocation payload: {"queue_url", "timeout_seconds"?, "heartbeat_timeout_seconds"?, "marker"}.
DURABLE_CALLBACK_HANDLER_SRC = """
import boto3
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig

_sqs = boto3.client("sqs")


@durable_step
def mark_started(step_context, marker):
    return {"marker": marker, "phase": "started"}


@durable_execution
def lambda_handler(event, context: DurableContext):
    queue_url = event["queue_url"]
    timeout_seconds = event.get("timeout_seconds", 0)
    heartbeat_timeout_seconds = event.get("heartbeat_timeout_seconds", 0)
    marker = event.get("marker", "m")

    context.step(mark_started(marker))

    def notify(callback_id, wait_for_callback_context):
        _sqs.send_message(QueueUrl=queue_url, MessageBody=callback_id)

    config_kwargs = {}
    if timeout_seconds:
        config_kwargs["timeout"] = Duration.from_seconds(timeout_seconds)
    if heartbeat_timeout_seconds:
        config_kwargs["heartbeat_timeout"] = Duration.from_seconds(heartbeat_timeout_seconds)

    result = context.wait_for_callback(
        notify,
        name="ext-callback",
        config=WaitForCallbackConfig(**config_kwargs),
    )
    return {"callback_result": result}
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc)
            # The classic "cannot be assumed by Lambda" IAM-propagation race, matched the same
            # way every other check in this directory matches it (code + "role" substring), not
            # just the narrower "does not have permissions" wording this file used alone.
            retryable = (code == "InvalidParameterValueException" and "role" in msg.lower()) or (
                "does not have permissions" in msg
            )
            if retryable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _durable_role_arn(ctx, *, sqs_send=False):
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
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in DURABLE_MANAGED_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    for pa in DURABLE_MANAGED_POLICIES:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=pa)
        except ClientError:
            pass
    if sqs_send:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="sqs-send",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                    "Resource": "*",
                }],
            }),
        )
    return arn


def _create_durable_function(ctx, lam, handler_source, *, execution_timeout=600,
                             retention_period_days=7, sqs_send=False):
    name = ctx.unique_name("sim2real-behav-durfn-")
    role_arn = _durable_role_arn(ctx, sqs_send=sqs_send)

    def _create():
        return lam.create_function(
            FunctionName=name,
            Runtime=DURABLE_RUNTIME,
            Role=role_arn,
            Handler=DURABLE_HANDLER_ENTRY,
            Code={"ZipFile": _make_zip(handler_source, "lambda_function.py")},
            Timeout=120,
            MemorySize=128,
            DurableConfig={
                "ExecutionTimeout": execution_timeout,
                "RetentionPeriodInDays": retention_period_days,
            },
        )

    _create_with_role_retry(_create)
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name, timeout_s=120)
    return name


def _start_durable_execution(ctx, lam, function_name, qualifier, payload, *, invocation_type="Event"):
    execution_name = ctx.unique_name("sim2real-behav-durex-")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier=qualifier,
        InvocationType=invocation_type,
        DurableExecutionName=execution_name,
        Payload=json.dumps(payload).encode("utf-8"),
    )
    arn = resp.get("DurableExecutionArn")
    if not arn:
        found = _poll_until(
            lambda: lam.list_durable_executions_by_function(
                FunctionName=function_name, Qualifier=qualifier, DurableExecutionName=execution_name
            ),
            lambda r: len(r.get("DurableExecutions", [])) > 0,
            timeout_s=30,
            interval_s=2.0,
            description=f"durable execution {execution_name} to be listed",
        )
        arn = found["DurableExecutions"][0]["DurableExecutionArn"]
    return resp, arn, execution_name


def _create_destination_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dest-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_one(ctx, queue_url, *, timeout_s=120, wait_seconds=8):
    sqs = ctx.client("sqs")

    def _poll():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_seconds
        )
        return resp.get("Messages")

    messages = _poll_until(
        _poll, lambda m: bool(m), timeout_s=timeout_s, interval_s=1.0,
        description=f"a message to arrive on {queue_url}",
    )
    return messages[0]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Callback ops sent after the callback's own timeout window elapses get CallbackTimeoutException.

    Fails if durable functions are not usable in the target account/region.
    """
    lam = ctx.client("lambda")
    try:
        fn = _create_durable_function(
            ctx, lam, DURABLE_CALLBACK_HANDLER_SRC, execution_timeout=180, sqs_send=True
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"durable functions not usable in this account/region: {exc}") from None
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    queue_url, _ = _create_destination_queue(ctx)
    timeout_seconds = 8
    payload = {"queue_url": queue_url, "timeout_seconds": timeout_seconds, "marker": ctx.unique_name("m-")}
    resp, arn, _ = _start_durable_execution(ctx, lam, fn, v1, payload, invocation_type="Event")
    assert resp["StatusCode"] == 202, resp

    msg = _receive_one(ctx, queue_url, timeout_s=60)
    callback_id = msg["Body"]
    ctx.client("sqs").delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # Wait for the callback window to genuinely elapse: once it does, the SDK resumes the suspended
    # execution and it reaches a terminal state — a real, service-driven signal that the window closed.
    _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn),
        lambda r: r.get("Status") != "RUNNING",
        timeout_s=timeout_seconds + 90,
        interval_s=3.0,
        description=f"durable execution {arn} to leave RUNNING after its callback times out",
    )

    success_code, success_msg = _client_error(
        lambda: lam.send_durable_execution_callback_success(CallbackId=callback_id, Result=b"{}")
    )
    assert success_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a post-timeout Success callback, got {success_code}"
    )

    failure_code, failure_msg = _client_error(
        lambda: lam.send_durable_execution_callback_failure(
            CallbackId=callback_id, Error={"ErrorMessage": "too late", "ErrorType": "LateCallback"}
        )
    )
    assert failure_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a post-timeout Failure callback, got {failure_code}"
    )

    heartbeat_code, heartbeat_msg = _client_error(
        lambda: lam.send_durable_execution_callback_heartbeat(CallbackId=callback_id)
    )
    assert heartbeat_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a post-timeout Heartbeat callback, got {heartbeat_code}"
    )
    expected_msg = "The callback is either timed out or already completed"
    assert (success_msg, failure_msg, heartbeat_msg) == (expected_msg,) * 3, (
        f"post-timeout callback messages (success, failure, heartbeat): "
        f"{(success_msg, failure_msg, heartbeat_msg)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
