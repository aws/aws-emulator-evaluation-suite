"""events-scheduler-semantics-same-schedule-name-in-two-groups-is-isolated-and-survives-the-sibling-group-deletion."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-same-schedule-name-in-two-groups-is-isolated-and-survives-the-sibling-group-deletion"
GROUP = "state-machine"
SERVICES = ["scheduler"]

_FIRST_BUDGET_S = 180
_GROUP_GONE_BUDGET_S = 180
_AFTER_BUDGET_S = 180


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The same schedule name can exist in two groups at once, each listed and delivering only under
    its own group, and deleting group A (cascading to A's schedule) leaves B's identically named
    schedule intact and still firing.
    """
    sch = ctx.client("scheduler")
    queue = _create_queue(ctx, "sim2real-behav-sched-grp-iso-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])
    group_a = _create_group(ctx, "sim2real-behav-sched-grp-a-")
    group_b = _create_group(ctx, "sim2real-behav-sched-grp-b-")
    name = ctx.unique_name("sim2real-behav-sched-shared-")
    marker_a = ctx.unique_name("grp-a-")
    marker_b = ctx.unique_name("grp-b-")

    for group, marker in ((group_a, marker_a), (group_b, marker_b)):
        _create_schedule(
            ctx,
            Name=name,
            GroupName=group,
            ScheduleExpression="rate(1 minute)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=_target(queue["arn"], role_arn, marker),
        )

    arn_a = sch.get_schedule(Name=name, GroupName=group_a)["Arn"]
    arn_b = sch.get_schedule(Name=name, GroupName=group_b)["Arn"]
    assert arn_a != arn_b, f"two groups' schedules named {name!r} share one ARN {arn_a!r}"
    assert _listed(ctx, group_a) == [name], (
        f"group A lists {_listed(ctx, group_a)!r}, expected exactly [{name!r}]"
    )
    assert _listed(ctx, group_b) == [name], (
        f"group B lists {_listed(ctx, group_b)!r}, expected exactly [{name!r}]"
    )
    code, message = _error(lambda: sch.get_schedule(Name=name))
    assert code == "ResourceNotFoundException", (
        f"GetSchedule for {name!r} in the default group returned {code!r}; the name exists only in "
        f"groups A and B"
    )
    assert message == f"Schedule {name} does not exist.", (
        f"GetSchedule for {name!r} in the default group returned message {message!r}"
    )

    seen: dict[str, list[dict]] = {marker_a: [], marker_b: []}
    deadline = _deadline(ctx, _FIRST_BUDGET_S)
    while time.monotonic() < deadline and not (seen[marker_a] and seen[marker_b]):
        _drain_into(ctx, queue["url"], seen)
    assert seen[marker_a] and seen[marker_b], (
        f"both same-named schedules must deliver their own payload before the deletion: "
        f"A={len(seen[marker_a])} B={len(seen[marker_b])} within {_FIRST_BUDGET_S}s"
    )

    sch.delete_schedule_group(Name=group_a)
    deadline = _deadline(ctx, _GROUP_GONE_BUDGET_S)
    gone_code, gone_message = _SUCCEEDED
    while time.monotonic() < deadline:
        gone_code, gone_message = _outcome(lambda: sch.get_schedule_group(Name=group_a))
        if gone_code != _SUCCEEDED[0]:
            break
        _drain_into(ctx, queue["url"], seen)
    assert gone_code == "ResourceNotFoundException", (
        f"group A {group_a} still resolved (or failed with {gone_code!r}) {_GROUP_GONE_BUDGET_S}s "
        f"after DeleteScheduleGroup"
    )
    assert gone_message == f"Schedule group {group_a} does not exist.", (
        f"GetScheduleGroup for the deleted group A returned message {gone_message!r}"
    )
    member_code, member_message = _error(lambda: sch.get_schedule(Name=name, GroupName=group_a))
    assert member_code == "ResourceNotFoundException", (
        f"group A's cascade-deleted schedule {name!r} returned {member_code!r} instead of "
        f"ResourceNotFoundException; DeleteScheduleGroup must also remove its member schedule"
    )
    assert member_message == gone_message, (
        f"group A's cascade-deleted schedule {name!r} reported message {member_message!r}; expected "
        f"the group's own not-found message {gone_message!r}"
    )
    gone_at = datetime.datetime.now(datetime.timezone.utc)

    survivor = sch.get_schedule(Name=name, GroupName=group_b)
    assert survivor["Arn"] == arn_b and survivor["State"] == "ENABLED", (
        f"group B's schedule after A's deletion reads Arn={survivor['Arn']!r} "
        f"State={survivor['State']!r}; expected {arn_b!r} ENABLED"
    )
    assert _listed(ctx, group_b) == [name], (
        f"after group A's deletion group B lists {_listed(ctx, group_b)!r}, expected [{name!r}]"
    )

    deadline = _deadline(ctx, _AFTER_BUDGET_S)

    def _b_after() -> list[str]:
        return [m["t"] for m in seen[marker_b] if _as_utc(m["t"]) > gone_at]

    while time.monotonic() < deadline and not _b_after():
        _drain_into(ctx, queue["url"], seen)
    assert _b_after(), (
        f"group B's schedule {name!r} delivered no occurrence scheduled after group A was deleted "
        f"({gone_at.isoformat()}) within {_AFTER_BUDGET_S}s; A's cascade reached a schedule in "
        f"another group. B saw {sorted(m['t'] for m in seen[marker_b])!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_CREATE_TIMEOUT_S = 150


# What _outcome reports for a call that succeeded: a pair no AWS error can equal.
_SUCCEEDED = ("<call succeeded>", "<call succeeded>")


def _outcome(fn) -> tuple[str, str]:
    """The (code, message) fn raised, or _SUCCEEDED when it succeeded."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "<no message>")
    return _SUCCEEDED


def _error(fn) -> tuple[str, str]:
    """The (code, message) fn raised; an unexpected SUCCESS fails loudly."""
    got = _outcome(fn)
    if got == _SUCCEEDED:
        raise AssertionError("the call was expected to fail but SUCCEEDED")
    return got


def _listed(ctx, group: str) -> list[str]:
    pages = ctx.client("scheduler").get_paginator("list_schedules").paginate(GroupName=group)
    return sorted(s["Name"] for page in pages for s in page["Schedules"])


def _create_group(ctx, prefix: str) -> str:
    sch = ctx.client("scheduler")
    name = ctx.unique_name(prefix)
    sch.create_schedule_group(Name=name, Tags=_MANAGED_TAGS_KV)
    ctx.on_cleanup(lambda: _delete_group(ctx, name))
    return name


def _delete_group(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
    # IAM propagates asynchronously: _create_schedule retries the propagation error until it clears.
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying ONLY the IAM-propagation ValidationException (its message names
    the role) within a bound. Cleanup is registered from the name passed to the accepted call."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = _deadline(ctx, _CREATE_TIMEOUT_S)
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
            time.sleep(2)
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
