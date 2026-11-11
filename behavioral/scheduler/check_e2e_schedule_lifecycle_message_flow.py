"""e2e-schedule-lifecycle-message-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-schedule-lifecycle-message-flow"
GROUP = "e2e"
SERVICES = ["scheduler"]

#: First-delivery deadline: the default class budget (300 s harness ceiling) less setup time.
_FIRST_DELIVERY_S = 240


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreateSchedule targeting SQS delivers messages; DeleteSchedule stops further delivery."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-life-")
    marker = ctx.unique_name("lifecycle-")

    scheduler = ctx.client("scheduler")
    target = {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker}),
    }
    _retry_role_not_ready(lambda: scheduler.create_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
    ))
    created_at = time.monotonic()
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    # rate(1 minute) fires roughly every 60s; the role was already warmed up above. The
    # first-delivery latency L sizes the post-delete absence window below.
    delivered = _wait_for_marker(ctx, queue_url, marker, timeout_s=_FIRST_DELIVERY_S, poll_interval=10)
    assert delivered, "expected at least one message delivered by the enabled schedule"
    first_latency_s = time.monotonic() - created_at

    listed = _listed(scheduler, schedule_name, group_name)
    assert listed == [schedule_name], f"expected the NamePrefix listing to be [{schedule_name!r}], got {listed!r}"
    scheduler.delete_schedule(Name=schedule_name, GroupName=group_name)

    # The delete must be real: an independent read 404s, the filtered listing is empty, and
    # mutations on the now-dead id (update, a second delete) fail the same way.
    _assert_schedule_gone(scheduler, schedule_name, group_name, target)

    # Grace window: an invocation already committed by the scheduler at the moment
    # DeleteSchedule was called may still land; drain silently before asserting.
    _drain_queue(ctx, queue_url, duration_s=20, poll_interval=10)

    # After the grace window, hold absence for max(90 s, 3L): more than one whole interval and
    # at least three times the latency this target showed for the positive delivery.
    still_arriving = _wait_for_marker(
        ctx, queue_url, marker, timeout_s=max(90.0, 3 * first_latency_s), poll_interval=10)
    assert not still_arriving, "message with the schedule's marker still arrived after DeleteSchedule"

    # Second independent observable: the queue's own reported counters must agree with
    # the empty receive above, not just "we didn't happen to poll one in".
    _assert_queue_empty(ctx, queue_url)


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, queue_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_role_ready(ctx, role["Arn"], queue_arn)
    return role["Arn"]


def _wait_for_role_ready(ctx, role_arn, queue_arn, max_wait_s=45, interval_s=5):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    scheduler = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                GroupName="default",
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps({"marker": "warmup"})},
            )
            scheduler.delete_schedule(Name=probe_name, GroupName="default")
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_group(ctx):
    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-sched-grp-")
    scheduler.create_schedule_group(Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, name))
    return name


def _assert_not_found(fn, what, expected_message):
    """fn must fail ResourceNotFoundException, HTTP 404, with the exact message."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException {what}, got {err['Code']}"
        )
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx {what}, got {status!r}"
        assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'
    else:
        raise AssertionError(f"expected the call {what} to fail, but it succeeded")


def _listed(scheduler, name, group_name):
    listed = []
    for page in scheduler.get_paginator("list_schedules").paginate(
            GroupName=group_name, NamePrefix=name):
        listed.extend(s["Name"] for s in page.get("Schedules", []))
    return listed


def _assert_schedule_gone(scheduler, name, group_name, target):
    """The delete is real -- an independent read 404s, the filtered listing is empty, and
    mutations on the now-dead id (UpdateSchedule, a second delete) fail the same way."""
    _assert_not_found(lambda: scheduler.get_schedule(Name=name, GroupName=group_name),
                      "reading the deleted schedule", f"Schedule {name} does not exist.")

    listed = _listed(scheduler, name, group_name)
    assert listed == [], f"the deleted schedule is still listed: {listed!r}"

    _assert_not_found(lambda: scheduler.update_schedule(
        Name=name, GroupName=group_name, ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"}, Target=target),
        "updating the deleted schedule", f"Schedule {name} does not exist.")

    _assert_not_found(lambda: scheduler.delete_schedule(Name=name, GroupName=group_name),
                      "on double-delete", f"Schedule {name} does not exist.")


def _assert_queue_empty(ctx, queue_url):
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    visible = int(attrs["ApproximateNumberOfMessages"])
    in_flight = int(attrs["ApproximateNumberOfMessagesNotVisible"])
    assert visible == 0 and in_flight == 0, (
        f"queue attributes report {visible} visible / {in_flight} in-flight message(s) after "
        "the negative delivery window, contradicting the empty receive"
    )


def _delete_schedule_safe(ctx, name, group_name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule(Name=name, GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_group_safe(ctx, name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_role_not_ready(fn, max_wait_s=90, interval_s=5):
    """Retry fn() while Scheduler reports the freshly-created execution role isn't usable yet
    (IAM trust-policy propagation delay), up to max_wait_s. Any other error is re-raised."""
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _drain_queue(ctx, queue_url, duration_s, poll_interval=10):
    """Receive-and-delete anything on the queue for duration_s, discarding it (grace window)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(poll_interval, 20)
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _wait_for_marker(ctx, queue_url, marker, timeout_s, poll_interval=10):
    """Poll the queue up to timeout_s; return True as soon as a message carrying `marker` is
    seen, False if none arrives."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    found = False
    while time.monotonic() < deadline and not found:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(poll_interval, 20)
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            if body.get("marker") == marker:
                found = True
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
