"""scheduler-lambda-flexible-time-window-invocation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scheduler-lambda-flexible-time-window-invocation"
GROUP = "event-propagation"
SERVICES = ["lambda", "scheduler"]

_SINK_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(
        QueueUrl=os.environ["SINK_QUEUE_URL"],
        MessageBody=json.dumps({"event": event}),
    )
    return {"ok": True}
"""

_WINDOW_MINUTES = 1


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule with a FlexibleTimeWindow invokes its Lambda target no earlier than the nominal
    fire time and no later than the window's close (plus delivery slack); both bounds are needed,
    or a target that fires on creation would pass."""
    queue = _create_sink_queue(ctx)
    lambda_role_arn = _create_lambda_role(ctx, queue["arn"])
    fn = _create_sink_function(ctx, lambda_role_arn, queue["url"])
    sched_role_arn = _create_scheduler_role(ctx, fn["arn"])

    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-flex-")
    when = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=60)
    _create_schedule_with_retry(
        scheduler,
        Name=name,
        ScheduleExpression=f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": _WINDOW_MINUTES},
        Target={
            "Arn": fn["arn"],
            "RoleArn": sched_role_arn,
            "Input": json.dumps({"marker": "flexible-window-test"}),
        },
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    collected: list[tuple[dict[str, Any], int]] = []

    def probe():
        collected.extend(_drain_queue_once(ctx, queue["url"]))
        return collected

    # scheduled_time (60s out) + the flexible window + generous grace for delivery lag.
    outer_bound_s = 60.0 + (_WINDOW_MINUTES * 60.0) + 120.0
    _poll_until(
        probe,
        lambda msgs: len(msgs) >= 1,
        timeout_s=outer_bound_s,
        interval_s=2.0,
        description="flexible-time-window schedule invocation delivered within window bound",
    )
    body, sent_ms = collected[0]
    assert body["event"]["marker"] == "flexible-window-test", (
        f"expected marker 'flexible-window-test', got {body!r}"
    )

    nominal_ms = int(when.timestamp() * 1000)
    window_end_ms = nominal_ms + int(_WINDOW_MINUTES * 60 * 1000)
    # Lambda cold-start + SQS send/delivery lag on top of the boundary itself.
    slack_ms = 30_000
    assert sent_ms >= nominal_ms - slack_ms, (
        f"flexible-window invocation reached the Lambda target before its nominal fire time: "
        f"sent={sent_ms} nominal={nominal_ms}"
    )
    assert sent_ms <= window_end_ms + slack_ms, (
        f"flexible-window invocation reached the Lambda target after its window closed: "
        f"sent={sent_ms} window_end={window_end_ms}"
    )


# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true"}
_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]

_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _scheduler_trust_policy(principal: str = "scheduler.amazonaws.com") -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, role_name, trust_policy, inline_policy=None, inline_policy_name="inline"):
    iam = ctx.client("iam")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_MANAGED_TAGS_KV,
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    if inline_policy is not None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=inline_policy_name,
            PolicyDocument=json.dumps(inline_policy),
        )
    return role_arn


def _create_sink_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sink-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _create_lambda_role(ctx, queue_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-behav-lambda-role-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    return _create_role(ctx, role_name, _LAMBDA_TRUST_POLICY, inline_policy=policy)


def _create_function_with_retry(ctx, params, timeout_s: float = 60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**params)
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")


def _create_sink_function(ctx, role_arn, queue_url, code=_SINK_CODE, timeout=10) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    resp = _create_function_with_retry(
        ctx,
        {
            "FunctionName": name,
            "Runtime": "python3.12",
            "Role": role_arn,
            "Handler": "index.handler",
            "Code": {"ZipFile": _zip_bytes(code)},
            "Timeout": timeout,
            "Environment": {"Variables": {"SINK_QUEUE_URL": queue_url}},
            "Tags": _MANAGED_TAGS,
        },
    )
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return {"name": name, "arn": arn}


def _create_scheduler_role(
    ctx, target_arn, trust_principal: str = "scheduler.amazonaws.com", grant_invoke: bool = True
) -> str:
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    inline = None
    if grant_invoke:
        inline = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": target_arn}
            ],
        }
    return _create_role(ctx, role_name, _scheduler_trust_policy(trust_principal), inline_policy=inline)


def _create_schedule_with_retry(scheduler, timeout_s: float = 45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except scheduler.exceptions.ValidationException as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"create_schedule never succeeded (role propagation?): {last_err}")


def _drain_queue_once(ctx, queue_url, max_messages=10, wait_time=5) -> list[tuple[dict[str, Any], int]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=wait_time,
        AttributeNames=["SentTimestamp"],
    )
    out: list[tuple[dict[str, Any], int]] = []
    for msg in resp.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            body = {"raw": msg["Body"]}
        sent_ms = int(msg["Attributes"]["SentTimestamp"])
        out.append((body, sent_ms))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
