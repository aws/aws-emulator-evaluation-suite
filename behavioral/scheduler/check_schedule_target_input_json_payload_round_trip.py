"""schedule-target-input-json-payload-round-trip."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "schedule-target-input-json-payload-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """Target.Input with escaped quotes/unicode round-trips through GetSchedule and is delivered
    to the SQS target byte-for-byte unchanged (no re-serialization by the scheduler backend)."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-q-"),
        tags={"sim2real-behav-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, sqs_send_arn=queue_arn)

    payload = json.dumps(
        {
            "quote": 'She said "hello" ↔ 你好 🎉',
            "backslash": "C:\\temp\\path",
            "nested": {"emoji": "🚀✨", "escaped": "line1\\nline2"},
        }
    )

    name = ctx.unique_name("sim2real-behav-sched-")
    fire_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=120)
    fire_at_str = fire_at.strftime("%Y-%m-%dT%H:%M:%S")

    _create_schedule_with_retry(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression=f"at({fire_at_str})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": payload},
        ActionAfterCompletion="NONE",
    )
    ctx.on_cleanup(lambda: _delete_schedule_if_present(scheduler, name))

    got = scheduler.get_schedule(Name=name)
    assert got["Target"]["Input"] == payload, (
        f"stored Target.Input differs: wrote {payload!r}, got {got['Target']['Input']!r}"
    )

    message = _poll_for_message(sqs, queue_url, timeout_s=240.0)
    assert message is not None, "schedule never delivered a message to the SQS target"
    assert message == payload, f"delivered body differs: wrote {payload!r}, got {message!r}"

    scheduler.delete_schedule(Name=name)
    try:
        scheduler.get_schedule(Name=name)
        raise AssertionError(f"schedule {name} still visible via GetSchedule after DeleteSchedule")
    except scheduler.exceptions.ResourceNotFoundException as exc:
        got_message = exc.response["Error"].get("Message")
        expected = f"Schedule {name} does not exist."
        assert got_message == expected, f"expected {expected!r}, got {got_message!r}"


def _create_scheduler_role(ctx, sqs_send_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-behav-sched-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sqs_send_arn}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _create_schedule_with_retry(ctx, scheduler, **kwargs):
    """CreateSchedule can transiently reject a freshly-created RoleArn while IAM trust-policy
    propagation is still in flight -- surfaced either as ResourceNotFoundException or as a
    ValidationException whose message complains the role must allow EventBridge Scheduler to
    assume it. Retry briefly on those transient signatures only."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except scheduler.exceptions.ResourceNotFoundException as exc:
            last_err = exc
            time.sleep(2.0)
        except scheduler.exceptions.ValidationException as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "must allow" not in msg and "assume" not in msg:
                raise
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"CreateSchedule kept failing on role propagation: {last_err}")


def _delete_schedule_if_present(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name)
    except scheduler.exceptions.ResourceNotFoundException:
        pass


def _poll_for_message(sqs, queue_url: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
