"""e2e-schedule-missing-iam-permission-blocks-delivery-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-schedule-missing-iam-permission-blocks-delivery-rejected"
GROUP = "e2e"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule whose execution role lacks sqs:SendMessage on its target queue never delivers,
    while an otherwise-identical schedule with a permitted role delivers in the same window."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    good_queue = _create_queue(ctx, sqs, "good")
    bad_queue = _create_queue(ctx, sqs, "bad")

    good_role_arn = _create_scheduler_role_with_send_permission(ctx, [good_queue["arn"]])
    bad_role_arn = _create_bare_scheduler_role(ctx)

    good_name = ctx.unique_name("sim2real-sched-good-")
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=good_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": good_queue["arn"],
            "RoleArn": good_role_arn,
            "Input": json.dumps({"ok": True}),
        },
    )
    ctx.on_cleanup(
        lambda: _safe_ignore_not_found(lambda: scheduler.delete_schedule(Name=good_name))
    )

    bad_name = ctx.unique_name("sim2real-sched-bad-")
    _create_schedule_with_role_propagation_retry(
        scheduler,
        Name=bad_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": bad_queue["arn"],
            "RoleArn": bad_role_arn,
            "Input": json.dumps({"ok": False}),
        },
    )
    ctx.on_cleanup(
        lambda: _safe_ignore_not_found(lambda: scheduler.delete_schedule(Name=bad_name))
    )

    # Drain both queues concurrently over the full window so the under-permissioned
    # schedule gets an equal opportunity to fire.
    good_bodies, bad_messages = _drain_two_queues(
        sqs, good_queue["url"], bad_queue["url"], timeout_s=150.0
    )
    assert good_bodies, "positive control failed to deliver: no messages received"
    assert good_bodies[0] == {"ok": True}, f"positive control delivered unexpected body: {good_bodies[0]}"

    # The effect of the missing sqs:SendMessage permission is an absence of delivery,
    # not a client-facing error, since CreateSchedule does not eagerly validate
    # downstream authorization.
    assert bad_messages == [], f"delivery occurred despite missing IAM permission: {bad_messages}"


def _safe_ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_schedule_with_role_propagation_retry(
    scheduler, timeout_s: float = 30.0, interval_s: float = 3.0, **kwargs
) -> None:
    """IAM is eventually consistent: CreateSchedule can reject a just-created execution role
    with ValidationException until it propagates, so retry for a bounded window."""
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
        QueueName=ctx.unique_name(f"sim2real-sched-q{suffix}-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _scheduler_trust_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _create_scheduler_role_with_send_permission(ctx, queue_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-ok-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_scheduler_trust_policy()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_bare_scheduler_role(ctx) -> str:
    """A role scheduler.amazonaws.com can assume, but with zero attached permissions."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-bare-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_scheduler_trust_policy()),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _parse_body(body: str) -> Any:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body


def _drain_two_queues(
    sqs, good_url: str, bad_url: str, timeout_s: float, interval_s: float = 5.0
) -> tuple[list[Any], list[Any]]:
    """Poll both queues for the full window, collecting every message; never stopping early
    lets the negative side assert absence over the whole window."""
    deadline = time.monotonic() + timeout_s
    good_out: list[Any] = []
    bad_out: list[Any] = []
    while time.monotonic() < deadline:
        for url, out in ((good_url, good_out), (bad_url, bad_out)):
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                out.append(_parse_body(msg["Body"]))
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        time.sleep(max(0.0, interval_s - 5.0))
    return good_out, bad_out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
