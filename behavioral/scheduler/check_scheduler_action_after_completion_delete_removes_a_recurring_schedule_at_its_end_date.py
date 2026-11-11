"""scheduler-action-after-completion-delete-removes-a-recurring-schedule-at-its-end-date."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-action-after-completion-delete-removes-a-recurring-schedule-at-its-end-date"
GROUP = "state-machine"
SERVICES = ["scheduler"]

_START_OFFSET_S = 60
# 2.5 cadence periods, deliberately NOT a whole multiple, so EndDate falls strictly between two
# occurrences and "the last invocation" is unambiguous.
_WINDOW_S = 150
_CADENCE = "rate(1 minute)"
_DELIVERY_TIMEOUT_S = 300
# AWS documents deletion "after its last invocation" without a latency bound.
_DELETION_TIMEOUT_S = 240
_SURVIVOR_SETTLE_S = 30


# timing:real-time — schedule: 210 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-delete.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:representation", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """ActionAfterCompletion=DELETE removes a recurring schedule once its EndDate passes (Get and
    UpdateSchedule then fail ResourceNotFoundException), while otherwise identical NONE+EndDate and
    DELETE-without-EndDate schedules survive; every arm must deliver first.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-delete.html
    """
    sch = ctx.client("scheduler")

    queue = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue["arn"])

    # Anchor the window AFTER provisioning: IAM propagation can hold CreateSchedule off, and a
    # StartDate computed before that could already be in the past when the call is accepted.
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    start_date = now + datetime.timedelta(seconds=_START_OFFSET_S)
    end_date = start_date + datetime.timedelta(seconds=_WINDOW_S)

    marker_delete = ctx.unique_name("delete-at-end-")
    marker_keep = ctx.unique_name("none-at-end-")
    marker_no_end = ctx.unique_name("delete-no-end-")

    name_delete = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        StartDate=start_date,
        EndDate=end_date,
        ActionAfterCompletion="DELETE",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_delete}),
        },
    )
    name_keep = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        StartDate=start_date,
        EndDate=end_date,
        ActionAfterCompletion="NONE",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_keep}),
        },
    )
    name_no_end = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        StartDate=start_date,
        ActionAfterCompletion="DELETE",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_no_end}),
        },
    )

    # Every arm must have fired before any is judged, so "gone" is distinct from "never ran".
    arrivals = _collect_markers(
        ctx,
        queue["url"],
        {marker_delete, marker_keep, marker_no_end},
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=(
            f"the three {_CADENCE} schedules {name_delete} / {name_keep} / {name_no_end}, all "
            f"starting at {start_date.isoformat()}"
        ),
    )
    for label, marker in (
        ("DELETE+EndDate", marker_delete),
        ("NONE+EndDate", marker_keep),
        ("DELETE-without-EndDate", marker_no_end),
    ):
        assert marker in arrivals, (
            f"the {label} arm never delivered within {_DELIVERY_TIMEOUT_S}s, so nothing about its "
            f"post-completion fate is attributable to ActionAfterCompletion: markers seen "
            f"{sorted(arrivals)!r}"
        )

    _poll_until(
        lambda: _get_schedule_outcome(sch, name_delete),
        lambda outcome: outcome == "ResourceNotFoundException",
        timeout_s=_DELETION_TIMEOUT_S,
        interval_s=10.0,
        description=(
            f"ActionAfterCompletion=DELETE to remove {name_delete} after its EndDate "
            f"{end_date.isoformat()} passed (its last invocation is the occurrence closest to that "
            f"instant)"
        ),
    )
    # A mutation on the deleted schedule must fail too, not silently resurrect it.
    update_code, update_message = _error_code(
        lambda: sch.update_schedule(
            Name=name_delete,
            ScheduleExpression=_CADENCE,
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": queue["arn"], "RoleArn": role_arn, "Input": "resurrect"},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"UpdateSchedule on the self-deleted {name_delete} returned {update_code!r}, expected "
        f"ResourceNotFoundException — a deleted schedule must be unusable, not merely unreadable"
    )
    assert update_message == f"Schedule {name_delete} does not exist.", (
        f"expected the not-found message for {name_delete!r}, got {update_message!r}"
    )
    listed = _list_schedule_names(ctx)
    assert name_delete not in listed, (
        f"{name_delete} is still enumerated by ListSchedules after ActionAfterCompletion=DELETE "
        f"removed it; GetSchedule and ListSchedules disagree"
    )

    # Survivors are read after the deletion is observed, and again after a settle interval.
    for label, name in (("NONE+EndDate", name_keep), ("DELETE-without-EndDate", name_no_end)):
        described = sch.get_schedule(Name=name)
        assert described["Name"] == name, (
            f"the {label} arm {name} must survive its completion; GetSchedule returned "
            f"{described.get('Name')!r}"
        )
        assert name in listed, (
            f"the {label} arm {name} is missing from ListSchedules while the DELETE+EndDate arm was "
            f"correctly removed: {sorted(listed)!r}"
        )
    keep_state = sch.get_schedule(Name=name_keep)
    assert keep_state["ActionAfterCompletion"] == "NONE", (
        f"the control arm reports ActionAfterCompletion "
        f"{keep_state['ActionAfterCompletion']!r}, expected 'NONE' — the two arms must differ in "
        f"exactly this field"
    )

    # Re-read the list throughout a bounded window so a survivor removed at any point is caught.
    still = _watch_schedule_names(ctx, window_s=_SURVIVOR_SETTLE_S)
    assert name_keep in still and name_no_end in still, (
        f"a survivor disappeared {_SURVIVOR_SETTLE_S}s after the DELETE+EndDate arm was removed, so "
        f"the deletion is not scoped to ActionAfterCompletion=DELETE with an EndDate: expected both "
        f"{name_keep!r} and {name_no_end!r}, saw {sorted(still)!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException; the bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-aac-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


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

    The cleanup tolerates the schedule having already removed itself.
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


def _get_schedule_outcome(sch, name: str) -> str:
    """`"present"` while GetSchedule still answers, else the error code it raised.

    Success is the expected early state of the poll, so it does not raise here.
    """
    try:
        sch.get_schedule(Name=name)
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    return "present"


def _error_code(call) -> tuple[str, str]:
    """The (code, message) a call raises; raises on unexpected success."""
    try:
        call()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return str(error.get("Code")), str(error.get("Message"))
    raise AssertionError(
        "the call succeeded where a specific error was required; nothing can be concluded about the "
        "error code because the operation was accepted"
    )


def _list_schedule_names(ctx) -> set[str]:
    """Every schedule name in the default group, following NextToken to exhaustion."""
    sch = ctx.client("scheduler")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = sch.list_schedules(**kwargs)
        for item in page["Schedules"]:
            names.add(item["Name"])
        token = page.get("NextToken")
        if not token:
            return names


def _watch_schedule_names(ctx, *, window_s: float) -> set[str]:
    """The intersection of every ListSchedules read over a bounded window; never raises."""
    surviving = _list_schedule_names(ctx)
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        time.sleep(10)
        surviving &= _list_schedule_names(ctx)
    return surviving


def _collect_markers(ctx, queue_url: str, wanted: set[str], *, timeout_s: float, description: str):
    """Poll until every marker in `wanted` has been seen, or the budget runs out.

    Returns {marker: body}; raises only when nothing at all arrived.
    """
    sqs = ctx.client("sqs")
    found: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and set(found) != wanted:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict) and body.get("marker") in wanted:
                found.setdefault(body["marker"], body)
    if not found:
        raise AssertionError(f"{description}: none of them delivered anything within {timeout_s}s")
    return found


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a stated reason; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
