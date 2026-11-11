"""events-scheduler-semantics-lapsed-window-schedule-delivers-nothing-scheduled-at-or-after-its-end-date."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-lapsed-window-schedule-delivers-nothing-scheduled-at-or-after-its-end-date"
GROUP = "server-side"
SERVICES = ["scheduler"]

# StartDate may be at most a few minutes in the past (measured: 20 min ago is rejected with
# "cannot be earlier than 5 minutes ago"); 3 minutes sits well inside that.
_START_AGO = datetime.timedelta(minutes=3)
# EndDate 90 s after StartDate: rate(1 minute) occurrences at S and S+60 fall inside the window,
# S+120 is the first outside it, and no occurrence lands ON EndDate.
_WINDOW = datetime.timedelta(seconds=90)
_TWIN_BUDGET_S = 240
_SETTLE_S = 20


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A recurring schedule whose [StartDate, EndDate) window is already past is ACCEPTED and delivers
    nothing scheduled at or after EndDate, while a twin with an open EndDate on the same queue and role
    delivers occurrences past it; backfill inside the window is not asserted either way.
    """
    sch = ctx.client("scheduler")
    queue = _create_queue(ctx, "sim2real-behav-sched-lapsed-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])

    created_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    start = created_at - _START_AGO
    end = start + _WINDOW
    assert end < created_at, f"precondition: EndDate {end.isoformat()} must already be in the past"

    lapsed_marker = ctx.unique_name("lapsed-")
    twin_marker = ctx.unique_name("open-")
    lapsed_name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        StartDate=start,
        EndDate=end,
        Target=_target(queue["arn"], role_arn, lapsed_marker),
    )
    twin_name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        StartDate=start,
        EndDate=created_at + datetime.timedelta(minutes=15),
        Target=_target(queue["arn"], role_arn, twin_marker),
    )

    stored = sch.get_schedule(Name=lapsed_name)
    assert stored["EndDate"].astimezone(datetime.timezone.utc) == end, (
        f"the lapsed schedule stored EndDate {stored['EndDate']!r}, expected {end.isoformat()}"
    )
    assert stored["State"] == "ENABLED", f"the lapsed schedule reads State={stored['State']!r}"

    # Positive control: wait for the twin to deliver an occurrence scheduled AFTER the moment both
    # schedules were created — a live occurrence, not a backfilled one.
    seen: dict[str, list[dict]] = {lapsed_marker: [], twin_marker: []}
    deadline = time.monotonic() + _TWIN_BUDGET_S

    def _twin_live() -> bool:
        return any(_as_utc(m["t"]) > created_at for m in seen[twin_marker])

    while time.monotonic() < deadline and not _twin_live():
        _drain_into(ctx, queue["url"], seen)
    assert _twin_live(), (
        f"the open-window twin {twin_name} delivered no occurrence scheduled after "
        f"{created_at.isoformat()} within {_TWIN_BUDGET_S}s (saw "
        f"{sorted(m['t'] for m in seen[twin_marker])!r}), so the lapsed schedule's silence cannot "
        f"be attributed to its EndDate"
    )
    settle = time.monotonic() + _SETTLE_S
    while time.monotonic() < settle:
        _drain_into(ctx, queue["url"], seen)

    twin_past_end = [m["t"] for m in seen[twin_marker] if _as_utc(m["t"]) >= end]
    assert twin_past_end, (
        f"the twin delivered nothing scheduled at or after {end.isoformat()}, so the dispatcher was "
        f"never shown to emit this grid past the lapsed EndDate: {seen[twin_marker]!r}"
    )
    late = sorted(m["t"] for m in seen[lapsed_marker] if _as_utc(m["t"]) >= end)
    assert late == [], (
        f"the lapsed schedule {lapsed_name} (EndDate {end.isoformat()}, already past at creation) "
        f"delivered occurrence(s) scheduled at or after its EndDate: {late!r}; the twin with the same "
        f"StartDate delivered {sorted(twin_past_end)!r} over the same period"
    )
    early = sorted(m["t"] for m in seen[lapsed_marker] if _as_utc(m["t"]) < start)
    assert early == [], (
        f"the lapsed schedule delivered occurrence(s) scheduled before its StartDate "
        f"{start.isoformat()}: {early!r}"
    )


# ===== helpers (self-contained) =====

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_ROLE_PROPAGATION_WAIT_S = 12
_CREATE_TIMEOUT_S = 150


def _target(queue_arn: str, role_arn: str, marker: str) -> dict:
    return {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker, "t": "<aws.scheduler.scheduled-time>"}),
    }


def _as_utc(rendered: str) -> datetime.datetime:
    parsed = datetime.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, f"scheduled-time {rendered!r} carries no zone designator"
    return parsed.astimezone(datetime.timezone.utc)


def _create_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _scheduler_role(ctx, queue_arns: list[str]) -> str:
    """An IAM role EventBridge Scheduler can assume, permitted to send to exactly these queues."""
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
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arns}],
            }
        ),
    )
    # IAM exposes no propagation condition; the bounded retry in _create_schedule is the wait.
    time.sleep(_ROLE_PROPAGATION_WAIT_S)
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying ONLY the IAM-propagation ValidationException (its message names
    the role) within a bound. Cleanup is registered from the name passed to the accepted call."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "ValidationException" or "role" not in err.get("Message", "").lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM propagation: {exc!r}"
                ) from exc
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


def _drain_into(ctx, queue_url: str, seen: dict[str, list[dict]]) -> None:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg.get("Body", ""))
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("marker") in seen:
            seen[body["marker"]].append(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
