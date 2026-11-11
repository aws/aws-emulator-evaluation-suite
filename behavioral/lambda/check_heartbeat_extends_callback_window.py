"""heartbeat-extends-callback-window."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "heartbeat-extends-callback-window"
GROUP = 'durable_execution'
SERVICES = ['lambda']

DURABLE_RUNTIME = "python3.13"
DURABLE_HANDLER_ENTRY = "lambda_function.lambda_handler"

DURABLE_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
)

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


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            propagating = "does not have permissions" in str(exc) or "cannot be assumed" in str(exc)
            if propagating and time.monotonic() < deadline:
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


def _sleep_until(started_at, seconds_after_start):
    remaining = started_at + seconds_after_start - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


# timing:real-time — workflow: 15 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A callback heartbeat sent at 0.4 of the 15 s heartbeat timeout resets the window: at 1.2 of the
    timeout, after the original deadline, the execution is still RUNNING, and it reaches SUCCEEDED
    once the callback succeeds."""
    lam = ctx.client("lambda")
    try:
        fn = _create_durable_function(
            ctx, lam, DURABLE_CALLBACK_HANDLER_SRC, execution_timeout=300, sqs_send=True
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"durable functions not usable in this account/region: {exc}") from None
    v1 = lam.publish_version(FunctionName=fn)["Version"]

    queue_url, _ = _create_destination_queue(ctx)
    heartbeat_timeout_seconds = 15
    payload = {
        "queue_url": queue_url,
        "heartbeat_timeout_seconds": heartbeat_timeout_seconds,
        "marker": ctx.unique_name("m-"),
    }
    resp, arn, _ = _start_durable_execution(ctx, lam, fn, v1, payload, invocation_type="Event")
    assert resp["StatusCode"] == 202, resp

    msg = _receive_one(ctx, queue_url, timeout_s=60)
    # notify() sends this message at callback registration, so its receipt is the best proxy
    # available for the callback's actual start time — anchoring on invoke() instead would fold
    # cold-start latency (which can run to tens of seconds) into the window math below.
    callback_started_at = time.monotonic()
    callback_id = msg["Body"]
    ctx.client("sqs").delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    # Heartbeat partway through the original window, so the original deadline (1.0H) and the
    # reset one (1.4H) are far enough apart to probe between them.
    _sleep_until(callback_started_at, heartbeat_timeout_seconds * 0.4)
    lam.send_durable_execution_callback_heartbeat(CallbackId=callback_id)

    # Strictly between the original deadline (1.0H) and the reset one (0.4H + 1.0H = 1.4H).
    _sleep_until(callback_started_at, heartbeat_timeout_seconds * 1.2)
    mid = lam.get_durable_execution(DurableExecutionArn=arn)
    assert mid["Status"] == "RUNNING", (
        f"execution left RUNNING (status={mid['Status']!r}) before the heartbeat-reset window "
        "should have elapsed; the heartbeat did not extend the timeout"
    )

    lam.send_durable_execution_callback_success(CallbackId=callback_id, Result=b"{}")
    final = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn),
        lambda r: r.get("Status") in ("SUCCEEDED", "FAILED"),
        timeout_s=60,
        interval_s=3.0,
        description=f"durable execution {arn} to reach a terminal state after the resolved callback",
    )
    assert final["Status"] == "SUCCEEDED", final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
