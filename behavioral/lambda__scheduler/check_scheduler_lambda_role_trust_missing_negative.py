"""scheduler-lambda-role-trust-missing-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scheduler-lambda-role-trust-missing-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "scheduler"]

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}

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


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule whose role does not trust scheduler.amazonaws.com never invokes its Lambda target,
    while an identically wired schedule whose role trusts it invokes the same function."""
    queue = _create_sink_queue(ctx)
    lambda_role_arn = _create_lambda_role(ctx, queue["arn"])
    fn = _create_sink_function(ctx, lambda_role_arn, queue["url"])

    good_role_arn = _create_scheduler_role(ctx, fn["arn"], trust_principal="scheduler.amazonaws.com")
    # Has the right *permission* (lambda:InvokeFunction) but the wrong *trust* principal -
    # scheduler.amazonaws.com can never sts:AssumeRole this one.
    untrusted_role_arn = _create_scheduler_role(ctx, fn["arn"], trust_principal="lambda.amazonaws.com")

    scheduler = ctx.client("scheduler")
    good_name = ctx.unique_name("sim2real-behav-goodtrust-")
    bad_name = ctx.unique_name("sim2real-behav-badtrust-")

    _create_schedule_with_retry(
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": fn["arn"],
            "RoleArn": good_role_arn,
            "Input": json.dumps({"marker": "good"}),
        },
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=good_name))

    # EventBridge Scheduler validates the execution role's trust policy synchronously at
    # CreateSchedule time, so a role that does not trust scheduler.amazonaws.com is rejected
    # up front (ValidationException) rather than silently accepted and never invoked. Both
    # outcomes prove the same thing: the untrusted role can never be used to invoke the target.
    bad_schedule_rejected = False
    bad_schedule_created = False
    deadline = time.monotonic() + 45.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            scheduler.create_schedule(
                Name=bad_name,
                ScheduleExpression="rate(1 minute)",
                FlexibleTimeWindow={"Mode": "OFF"},
                Target={
                    "Arn": fn["arn"],
                    "RoleArn": untrusted_role_arn,
                    "Input": json.dumps({"marker": "bad"}),
                },
                State="ENABLED",
            )
            bad_schedule_created = True
            ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=bad_name))
            break
        except scheduler.exceptions.ValidationException as exc:
            last_err = exc
            msg = str(exc)
            if "assume the role" in msg or "AssumeRole" in msg or "execution role" in msg:
                bad_schedule_rejected = True
                break
            # Could still be plain IAM-propagation flakiness on an unrelated validation - retry.
            time.sleep(3.0)

    assert bad_schedule_rejected or bad_schedule_created, (
        f"create_schedule for untrusted-role target neither succeeded nor was rejected "
        f"with the expected trust-policy validation error: {last_err}"
    )

    good_msgs: list[dict[str, Any]] = []

    bad_msgs: list[dict[str, Any]] = []

    def probe():
        for body in _drain_queue_once(ctx, queue["url"]):
            marker = body["event"].get("marker")
            if marker == "good":
                good_msgs.append(body)
            elif marker == "bad":
                bad_msgs.append(body)
        return good_msgs

    # Both rate(1 minute) schedules are created moments apart, so the control's second invocation
    # lands about a period after the broken schedule's first due tick: the bad marker is read only
    # after that tick has had most of a period to deliver.
    _poll_until(
        probe,
        lambda msgs: len(msgs) >= 2,
        timeout_s=240.0,
        interval_s=5.0,
        description="positive-control schedule (role trusts scheduler.amazonaws.com) invoked twice",
    )
    assert len(bad_msgs) == 0, f"schedule invoked target via an unassumable (untrusted) role: {bad_msgs}"


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
