"""e2e-update-schedule-target-redirects-invocation."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-update-schedule-target-redirects-invocation"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After confirming delivery to queue A, updating the schedule's target to queue B
    causes subsequent invocations to land in queue B and no longer in queue A."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_a = _create_queue(ctx, sqs, "a")
    queue_b = _create_queue(ctx, sqs, "b")
    role_arn = _create_scheduler_role(ctx, [queue_a["arn"], queue_b["arn"]])

    name = ctx.unique_name("sim2real-sched-")
    expr = "rate(1 minute)"
    ftw = {"Mode": "OFF"}
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=name,
        ScheduleExpression=expr,
        FlexibleTimeWindow=ftw,
        Target={"Arn": queue_a["arn"], "RoleArn": role_arn, "Input": json.dumps({"leg": "a"})},
    )
    ctx.on_cleanup(lambda: _safe_ignore_not_found(lambda: scheduler.delete_schedule(Name=name)))

    first = _wait_for_message_body(sqs, queue_a["url"], timeout_s=150.0)
    assert first == {"leg": "a"}, f"unexpected first-leg payload: {first}"

    # Redirect the target to queue B well ahead of the next ~60s firing window: the
    # rate(1 minute) schedule with FlexibleTimeWindow OFF fires deterministically, so an
    # update issued immediately after the first confirmed delivery has close to a full
    # period of lead time before the next invocation is evaluated.
    scheduler.update_schedule(
        Name=name,
        ScheduleExpression=expr,
        FlexibleTimeWindow=ftw,
        Target={"Arn": queue_b["arn"], "RoleArn": role_arn, "Input": json.dumps({"leg": "b"})},
    )

    second = _wait_for_message_body(sqs, queue_b["url"], timeout_s=150.0)
    assert second == {"leg": "b"}, f"unexpected second-leg payload: {second}"

    # Any invocation that still landed in queue A after the redirect would still be
    # sitting there (SQS retains unconsumed messages), so checking now is conclusive.
    stray = _drain_messages(sqs, queue_a["url"], timeout_s=10.0)
    assert stray == [], f"queue A received a message after the target redirect: {stray}"


def _safe_ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_schedule_with_role_propagation_retry(
    scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs
) -> None:
    """Freshly-created IAM roles/policies are eventually consistent: CreateSchedule can
    reject a just-minted execution role with a ValidationException until the role has
    propagated. Retry the create for a bounded window rather than treating this as a
    hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "execution role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_queue(ctx, sqs, suffix: str) -> dict[str, str]:
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-sched-q{suffix}-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _create_scheduler_role(ctx, queue_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-sched-sqs-send"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arns}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_message_body(
    sqs, queue_url: str, timeout_s: float = 150.0, interval_s: float = 5.0
) -> Any:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if messages:
            msg = messages[0]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                return json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                return msg["Body"]
        time.sleep(max(0.0, interval_s - 5.0))
    raise AssertionError(f"no message delivered to {queue_url} within {timeout_s}s")


def _drain_messages(sqs, queue_url: str, timeout_s: float, interval_s: float = 5.0) -> list[Any]:
    deadline = time.monotonic() + timeout_s
    out: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        time.sleep(max(0.0, interval_s - 5.0))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
