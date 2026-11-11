"""cfn-scheduler-schedule-in-place-at-update-delivers-retained-replacement-then-not-found."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-scheduler-schedule-in-place-at-update-delivers-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "scheduler", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_READ_CAP_S = 30.0
#: The one-time schedule fires this long after the update is sent, past the update itself.
_LEAD_S = 120
#: How long after its at() time the schedule may take to deliver; the cap only stops a hung poll.
_DELIVERY_CAP_S = 180.0
#: Allowance for the runner's clock against AWS's when judging an early delivery.
_SKEW_S = 5.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Scheduler's refusal of a schedule that no longer exists, keyed by its name.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Schedule {name} does not exist."


def _template(name: str, expression: str, payload: str, description: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "scheduler.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "send-to-queue",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Schedule": {
                    "Type": "AWS::Scheduler::Schedule",
                    # Name is create-only, so changing it replaces the schedule.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Description": description,
                        "ScheduleExpression": expression,
                        "FlexibleTimeWindow": {"Mode": "OFF"},
                        "State": "ENABLED",
                        "Target": {
                            "Arn": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                            "Input": payload,
                        },
                    },
                },
            },
            "Outputs": {
                "ScheduleArn": {"Value": {"Fn::GetAtt": ["Schedule", "Arn"]}},
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
                "QueueUrl": {"Value": {"Ref": "Queue"}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                "Partition": {"Value": {"Ref": "AWS::Partition"}},
            },
        }
    )


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CloudFormation schedule reads back as templated, updates in place and survives replacement.

    An in-place change to a one-time at() two minutes ahead delivers its Input to SQS, not earlier;
    a Name change under UpdateReplacePolicy Retain keeps the old schedule; delete: not found.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-scheduler-schedule.html
    """
    cfn = ctx.client("cloudformation")
    scheduler = ctx.client("scheduler")
    sqs = ctx.client("sqs")
    first = ctx.unique_name("sim2real-cfnsch-a-")
    second = ctx.unique_name("sim2real-cfnsch-b-")
    stack_name = ctx.unique_name("sim2real-cfnsch-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}
    later = _at(time.time() + 86400)

    # The replaced schedule is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_schedule(scheduler, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view and Scheduler's view of a schedule a day ahead
    one = ctx.unique_name("one-")
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, later, one, "first"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    partition = outputs["Partition"]
    assert _physical_ids(cfn, ref["stack"])["Schedule"] == first, (
        f"the schedule's physical id must be its Name {first!r}"
    )
    first_arn = f"arn:{partition}:scheduler:{ctx.region}:{ctx.account}:schedule/default/{first}"
    assert outputs["ScheduleArn"] == first_arn, f"GetAtt Schedule.Arn {outputs!r}"
    target = {"Arn": outputs["QueueArn"], "RoleArn": outputs["RoleArn"]}
    _eventually(
        ctx,
        _READ_CAP_S,
        lambda: _assert_schedule(scheduler, first, first_arn, later, one, "first", target),
    )

    # ---- 2. in-place: a one-time at() shortly ahead and a new Input, the same schedule; it fires
    two = ctx.unique_name("two-")
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    # The at() time is part of the update, so it is fixed just before the update is sent.
    fire_at = time.time() + _LEAD_S
    soon = _at(fire_at)
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, soon, two, "second"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Schedule"] == first, (
        "an in-place update keeps the schedule"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Schedule"), first, "Schedule")
    _eventually(
        ctx,
        _READ_CAP_S,
        lambda: _assert_schedule(scheduler, first, first_arn, soon, two, "second", target),
    )
    body, sent_ms = _receive_one(ctx, sqs, outputs["QueueUrl"], fire_at)
    assert body == two, f"the schedule must deliver its updated Input {two!r}, got {body!r}"
    assert sent_ms >= (int(fire_at) - _SKEW_S) * 1000, (
        f"a one-time schedule at {soon} must not deliver before then; SentTimestamp {sent_ms}"
    )

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new schedule, the old one kept
    three = ctx.unique_name("three-")
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, later, three, "third"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Schedule"] == second, (
        f"the replacement's physical id must be its Name {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Schedule"), first, second, "Schedule"
    )
    second_arn = f"arn:{partition}:scheduler:{ctx.region}:{ctx.account}:schedule/default/{second}"
    assert _outputs(stack)["ScheduleArn"] == second_arn, (
        f"GetAtt Schedule.Arn after replacement {_outputs(stack)!r}"
    )
    _eventually(
        ctx,
        _READ_CAP_S,
        lambda: _assert_schedule(scheduler, second, second_arn, later, three, "third", target),
    )
    _assert_schedule(scheduler, first, first_arn, soon, two, "second", target)

    # ---- 4. delete: Scheduler no longer knows the stack's schedule
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: scheduler.get_schedule(Name=second),
        _NOT_FOUND_CODE,
        f"schedule {second}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(name=second))
    assert got == want, f"GetSchedule after the stack delete answered {got!r}"


def _at(epoch_s: float) -> str:
    """A one-time schedule expression in UTC, to the second."""
    moment = datetime.datetime.fromtimestamp(int(epoch_s), tz=datetime.UTC)
    return f"at({moment.strftime('%Y-%m-%dT%H:%M:%S')})"


def _assert_schedule(scheduler, name, arn, expression, payload, description, target) -> None:
    """GetSchedule reports the template's schedule exactly."""
    got_schedule = scheduler.get_schedule(Name=name)
    got = {
        k: got_schedule.get(k)
        for k in (
            "Name",
            "GroupName",
            "Arn",
            "Description",
            "ScheduleExpression",
            "State",
            "FlexibleTimeWindow",
        )
    }
    got["Target"] = {k: got_schedule.get("Target", {}).get(k) for k in ("Arn", "RoleArn", "Input")}
    want = {
        "Name": name,
        "GroupName": "default",
        "Arn": arn,
        "Description": description,
        "ScheduleExpression": expression,
        "State": "ENABLED",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {**target, "Input": payload},
    }
    assert got == want, f"GetSchedule {name!r}: {got!r}, expected {want!r}"


def _receive_one(ctx, sqs, url: str, fire_at: float) -> tuple[str, int]:
    """Body and SentTimestamp of the first message, waiting up to the cap past *fire_at*."""
    cap = max(1.0, fire_at - time.time()) + _DELIVERY_CAP_S
    timeout = _budget_s(ctx, cap)
    deadline = time.monotonic() + timeout
    while True:
        messages = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=10,
            MessageSystemAttributeNames=["SentTimestamp"],
        ).get("Messages", [])
        if messages:
            for m in messages:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            assert len(messages) == 1, (
                f"one delivery expected, got {[m['Body'] for m in messages]!r}"
            )
            return messages[0]["Body"], int(messages[0]["Attributes"]["SentTimestamp"])
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before the schedule delivered to {url}")
            raise AssertionError(f"the schedule delivered nothing to {url} within {timeout:.0f}s")


def _delete_schedule(scheduler, name: str) -> None:
    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise


def _eventually(ctx, cap_s, probe):
    """Run *probe* until it stops failing an assert; past the cap its last assert fails."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe()
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before a read converged: {exc}") from None
                raise
        time.sleep(_POLL_S)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status.

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if teardown is None and _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown=teardown), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict, teardown: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"], teardown=teardown)
    _delete_stack(ctx, cfn, stack["StackId"], teardown=teardown)


def _teardown_left(teardown: dict) -> float:
    """Seconds, at least 1, to the deadline every teardown shares; the first to ask fixes it."""
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
