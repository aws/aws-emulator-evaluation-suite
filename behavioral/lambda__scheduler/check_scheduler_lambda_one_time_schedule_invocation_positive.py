"""scheduler-lambda-one-time-schedule-invocation-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scheduler-lambda-one-time-schedule-invocation-positive"
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


# timing:real-time — schedule: 150 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A one-time at() schedule invokes the Lambda target exactly once, then EventBridge
    Scheduler auto-deletes it (ActionAfterCompletion=DELETE) after that single invocation."""
    queue = _create_sink_queue(ctx)
    lambda_role_arn = _create_lambda_role(ctx, queue["arn"])
    fn = _create_sink_function(ctx, lambda_role_arn, queue["url"])
    sched_role_arn = _create_scheduler_role(ctx, fn["arn"])

    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-onetime-")
    when = datetime.now(timezone.utc) + timedelta(seconds=150)
    # Note: EventBridge Scheduler's TagResource only accepts a schedule-group ARN --
    # individual schedules cannot carry tags at all (confirmed against real AWS:
    # ValidationException on a schedule ARN). Nothing to tag here.
    _create_schedule_with_retry(
        scheduler,
        Name=name,
        ScheduleExpression=f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="DELETE",
        Target={
            "Arn": fn["arn"],
            "RoleArn": sched_role_arn,
            "Input": json.dumps({"marker": "one-time-test"}),
        },
        State="ENABLED",
    )
    # Best-effort cleanup in case the check fails before auto-deletion happens.
    def _cleanup_schedule():
        try:
            scheduler.delete_schedule(Name=name)
        except scheduler.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup_schedule)

    collected: list[dict[str, Any]] = []

    def probe_invocation():
        collected.extend(_drain_queue_once(ctx, queue["url"]))
        return collected

    _poll_until(
        probe_invocation,
        lambda msgs: len(msgs) >= 1,
        timeout_s=240.0,
        interval_s=5.0,
        description="one-time schedule invocation delivered to sink queue",
    )
    assert collected[0]["event"]["marker"] == "one-time-test", (
        f"expected marker 'one-time-test' in delivered event, got {collected[0]['event']!r}"
    )

    def probe_deleted():
        try:
            scheduler.get_schedule(Name=name)
            return False
        except scheduler.exceptions.ResourceNotFoundException:
            return True

    _poll_until(
        probe_deleted,
        lambda deleted: deleted is True,
        timeout_s=120.0,
        interval_s=5.0,
        description="schedule auto-deleted after its single invocation completed",
    )

    # Confirm exactly one invocation happened (no stray retries/duplicates). The schedule is
    # already gone (proven above), so a bounded long-poll -- not a bare sleep -- is enough to
    # catch any straggling duplicate delivery still in flight.
    collected.extend(_drain_queue_once(ctx, queue["url"], wait_time=10))
    assert len(collected) == 1, f"expected exactly one invocation, got {len(collected)}: {collected}"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        QueueName=ctx.unique_name("sim2real-behav-sink-"), tags={"sim2real": CHECK}
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
            "Tags": {"sim2real": CHECK},
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


def _drain_queue_once(ctx, queue_url, max_messages=10, wait_time=5) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_time
    )
    out: list[dict[str, Any]] = []
    for msg in resp.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            body = {"raw": msg["Body"]}
        out.append(body)
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
