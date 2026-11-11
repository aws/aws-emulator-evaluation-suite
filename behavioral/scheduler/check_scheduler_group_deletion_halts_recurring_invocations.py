"""scheduler-group-deletion-halts-recurring-invocations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-group-deletion-halts-recurring-invocations"
GROUP = 'state-machine'
SERVICES = ['scheduler']

_FIRST_DELIVERY_TIMEOUT_S = 300
_CASCADE_TIMEOUT_S = 180
_CADENCE_S = 60  # matches the schedule's own rate(1 minute)
# The MINIMUM silence window: two full cadence periods plus Scheduler's own delivery slack.
# Lengthening it only makes the check stricter.
_QUIET_WINDOW_TIMEOUT_S = 150
# A tick already committed by Scheduler's internal clock the instant before the delete landed can
# still be in flight when GetSchedule/GetScheduleGroup already answer 404 -- draining only "until
# empty" can declare victory before that straggler arrives, letting it land inside the strict watch
# window instead. Require the drain to run at least half a cadence period past cascade-confirmed
# before two consecutive empty receives are allowed to end it -- long enough to catch that
# straggler, short enough to leave headroom under the per-check timeout once the fixed
# quiet window (below) is added on top.
_DRAIN_MIN_S = _CADENCE_S // 2
_DRAIN_TIMEOUT_S = 75


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Deleting a schedule group holding a live rate(1 minute) schedule makes GetScheduleGroup and
    GetSchedule return ResourceNotFoundException, and once the schedule has fired and the queue is
    drained, no further invocation reaches the target queue.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    # Registered BEFORE any member exists: a leaked group holding a rate() schedule fires forever.
    group = ctx.unique_name("sim2real-behav-sched-grp-")
    sch.create_schedule_group(
        Name=group, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _delete_group(ctx, group))

    marker = ctx.unique_name("marker-")
    name = _create_schedule(
        ctx,
        GroupName=group,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker}),
        },
    )

    # (1) The barrier: prove the schedule is live BEFORE breaking anything.
    first = _await_body(
        ctx,
        queue_url,
        lambda b: b.get("marker") == marker,
        timeout_s=_FIRST_DELIVERY_TIMEOUT_S,
        description=f"the schedule {name} in group {group} delivering before its group is deleted",
    )
    assert first is not None, (
        f"the schedule {name} in group {group} never delivered, so a later halt cannot be "
        f"attributed to the group deletion"
    )

    # (2) Break exactly one thing: delete the group.
    sch.delete_schedule_group(Name=group)
    _poll_until(
        lambda: _group_state(ctx, group),
        lambda state: state == "ABSENT",
        timeout_s=_CASCADE_TIMEOUT_S,
        description=f"the schedule group {group} becoming absent",
    )

    group_missing = f"Schedule group {group} does not exist."
    assert _error(lambda: sch.get_schedule_group(Name=group)) == (
        "ResourceNotFoundException",
        group_missing,
    ), f"the schedule group {group} was not deleted"
    assert _error(lambda: sch.get_schedule(Name=name, GroupName=group)) == (
        "ResourceNotFoundException",
        group_missing,
    ), f"the member schedule {name} survived the deletion of its group {group}"

    # (3) Retire anything dispatched before the deletion landed, then watch.
    _drain_to_empty(ctx, queue_url, timeout_s=_DRAIN_TIMEOUT_S, min_duration_s=_DRAIN_MIN_S)
    strays = _collect_all(
        ctx,
        queue_url,
        lambda b: b.get("marker") == marker,
        window_s=_QUIET_WINDOW_TIMEOUT_S,
    )
    assert not strays, (
        f"{len(strays)} invocation(s) reached the target queue during the "
        f"{_QUIET_WINDOW_TIMEOUT_S}s after the schedule group {group} was fully deleted -- the "
        f"timer did not stop: {strays!r}"
    )

    # Second, independent observable: the queue's own depth counter, not just what a receive
    # sampled. Guards against a target that dispatches but the poll above missed a redelivery.
    sqs = ctx.client("sqs")
    depth = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert depth["ApproximateNumberOfMessages"] == "0" and depth[
        "ApproximateNumberOfMessagesNotVisible"
    ] == "0", (
        f"queue {queue_url} reports non-zero depth after the quiet window even though no stray "
        f"body was received: {depth!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. `_create_schedule`'s bounded retry (below) is the
# wait -- there is no separate sleep here, unconditional or otherwise.
_CREATE_TIMEOUT_S = 180


def _error(fn):
    """The AWS error (code, message) a call raised. Raises if the call unexpectedly SUCCEEDS, so a
    success can never be confused with a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to fail but succeeded")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _scheduler_role(ctx, queue_arn: str) -> str:
    """An IAM role EventBridge Scheduler can assume, permitted to send to exactly this queue."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
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
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    The cleanup is registered from the name passed to the accepted call -- never re-looked-up.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _group_state(ctx, group: str) -> str:
    """The group's State, or 'ABSENT' once it is gone. A pollable probe -- unlike `_error`,
    which deliberately raises when the call succeeds."""
    try:
        return ctx.client("scheduler").get_schedule_group(Name=group)["State"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "ABSENT"
        raise


def _delete_group(ctx, group: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule_group(Name=group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(2)
    raise AssertionError(f"{description} not observed within {timeout_s}s. Last: {last!r}")


def _await_body(ctx, queue_url, predicate, *, timeout_s, description):
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(body, dict):
                continue
            seen.append(body)
            if predicate(body):
                return body
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. Bodies seen: {seen!r}"
    )


def _drain_to_empty(ctx, queue_url, *, timeout_s, min_duration_s=0.0, consecutive_empty=2):
    """Drain until `consecutive_empty` receives come back empty AND at least `min_duration_s` has
    elapsed, so a tick already committed before the break -- whose delivery lags the metadata going
    404 -- cannot slip past a premature "empty" into the strict watch window."""
    sqs = ctx.client("sqs")
    start = time.monotonic()
    empties = 0
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            empties += 1
        else:
            empties = 0
            for msg in msgs:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if empties >= consecutive_empty and time.monotonic() - start >= min_duration_s:
            return


def _collect_all(ctx, queue_url, predicate, *, window_s):
    """Watch for a bounded window and return every matching body. Never raises."""
    sqs = ctx.client("sqs")
    found: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict) and predicate(body):
                found.append(body)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
