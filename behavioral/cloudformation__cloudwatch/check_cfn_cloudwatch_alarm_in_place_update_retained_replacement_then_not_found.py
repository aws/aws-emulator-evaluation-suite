"""cfn-cloudwatch-alarm-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cloudwatch-alarm-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: CloudWatch serves a changed alarm within seconds; the cap only stops a hung poll.
_READ_CAP_S = 30.0
#: A state change reaches the alarm history within seconds; the cap only stops a hung poll.
_HISTORY_CAP_S = 60.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NAMESPACE = "Sim2Real/CfnAlarm"
_METRIC = "Signal"

#: SetAlarmState's refusal of an alarm that does not exist: the short code and no message.
_NOT_FOUND = ("ResourceNotFound", "")


def _template(alarm_name: str, dimension: str, threshold: int, description: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Alarm": {
                    "Type": "AWS::CloudWatch::Alarm",
                    # AlarmName is create-only, so changing it replaces the alarm.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "AlarmName": alarm_name,
                        "AlarmDescription": description,
                        "ActionsEnabled": False,
                        "Namespace": _NAMESPACE,
                        "MetricName": _METRIC,
                        "Dimensions": [{"Name": "Check", "Value": dimension}],
                        "Statistic": "Sum",
                        "Period": 60,
                        "EvaluationPeriods": 1,
                        "Threshold": threshold,
                        "ComparisonOperator": "GreaterThanThreshold",
                        "TreatMissingData": "missing",
                    },
                },
            },
            "Outputs": {
                "AlarmArn": {"Value": {"Fn::GetAtt": ["Alarm", "Arn"]}},
                "Partition": {"Value": {"Ref": "AWS::Partition"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation alarm reads back as templated, updates in place and survives replacement.

    SetAlarmState drives it to ALARM in its history; a Threshold change keeps the alarm, an
    AlarmName change under UpdateReplacePolicy Retain keeps the old alarm; delete: ResourceNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    first = ctx.unique_name("sim2real-cfnalarm-a-")
    second = ctx.unique_name("sim2real-cfnalarm-b-")
    dimension = ctx.unique_name("dim-")
    stack_name = ctx.unique_name("sim2real-cfnalarm-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The replaced alarm is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[first]))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, CloudWatch's view, and a state change
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, dimension, 10, "first"),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = _outputs(stack)["Partition"]
    assert _physical_ids(cfn, ref["stack"])["Alarm"] == first, (
        f"the alarm's physical id must be its AlarmName {first!r}"
    )
    first_arn = f"arn:{partition}:cloudwatch:{ctx.region}:{ctx.account}:alarm:{first}"
    assert _outputs(stack)["AlarmArn"] == first_arn, f"GetAtt Alarm.Arn {_outputs(stack)!r}"
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_alarm(cw, first, first_arn, dimension, 10.0, "first")
    )
    _assert_set_state(ctx, cw, first, "ALARM")

    # ---- 2. in-place: a new Threshold and description, the same alarm
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, dimension, 20, "second"),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Alarm"] == first, "an in-place update keeps the alarm"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Alarm"), first, "Alarm")
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_alarm(cw, first, first_arn, dimension, 20.0, "second")
    )
    _assert_set_state(ctx, cw, first, "OK")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new alarm, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, dimension, 20, "second"),
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Alarm"] == second, (
        f"the replacement's physical id must be its AlarmName {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Alarm"), first, second, "Alarm"
    )
    second_arn = f"arn:{partition}:cloudwatch:{ctx.region}:{ctx.account}:alarm:{second}"
    assert _outputs(stack)["AlarmArn"] == second_arn, (
        f"GetAtt Alarm.Arn after replacement {_outputs(stack)!r}"
    )
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_alarm(cw, second, second_arn, dimension, 20.0, "second")
    )
    _assert_set_state(ctx, cw, second, "ALARM")
    _assert_alarm(cw, first, first_arn, dimension, 20.0, "second")

    # ---- 4. delete: CloudWatch no longer knows the stack's alarm; the retained one remains
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: cw.set_alarm_state(AlarmName=second, StateValue="OK", StateReason="signal"),
        _NOT_FOUND[0],
        f"alarm {second}",
    )
    assert got == _NOT_FOUND, f"SetAlarmState after the stack delete answered {got!r}"
    alarms = cw.describe_alarms(AlarmNames=[first, second])["MetricAlarms"]
    names = [a["AlarmName"] for a in alarms]
    assert names == [first], f"only the retained alarm {first!r} must remain, got {names!r}"


def _assert_alarm(cw, name: str, arn: str, dimension: str, threshold: float, description: str):
    """DescribeAlarms reports exactly the template's alarm definition."""
    alarms = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms {name!r} returned {alarms!r}"
    alarm = alarms[0]
    keys = (
        "AlarmName",
        "AlarmArn",
        "AlarmDescription",
        "ActionsEnabled",
        "AlarmActions",
        "Namespace",
        "MetricName",
        "Dimensions",
        "Statistic",
        "Period",
        "EvaluationPeriods",
        "Threshold",
        "ComparisonOperator",
        "TreatMissingData",
    )
    got = {k: alarm.get(k) for k in keys}
    want = {
        "AlarmName": name,
        "AlarmArn": arn,
        "AlarmDescription": description,
        "ActionsEnabled": False,
        "AlarmActions": [],
        "Namespace": _NAMESPACE,
        "MetricName": _METRIC,
        "Dimensions": [{"Name": "Check", "Value": dimension}],
        "Statistic": "Sum",
        "Period": 60,
        "EvaluationPeriods": 1,
        "Threshold": threshold,
        "ComparisonOperator": "GreaterThanThreshold",
        "TreatMissingData": "missing",
    }
    assert got == want, f"DescribeAlarms {name!r}: {got!r}, expected {want!r}"


def _assert_set_state(ctx, cw, name: str, state: str) -> None:
    """SetAlarmState is recorded as a StateUpdate whose new state carries the given reason."""
    reason = ctx.unique_name("sim2real-reason-")
    cw.set_alarm_state(AlarmName=name, StateValue=state, StateReason=reason)

    def probe():
        items = cw.describe_alarm_history(
            AlarmName=name, HistoryItemType="StateUpdate", MaxRecords=100
        )["AlarmHistoryItems"]
        # A later re-evaluation carries the reason as its oldState, so only newState counts.
        new_states = [json.loads(i.get("HistoryData") or "{}").get("newState", {}) for i in items]
        mine = [s for s in new_states if s.get("stateReason") == reason]
        want = [{"stateValue": state, "stateReason": reason}]
        got = [{k: s.get(k) for k in ("stateValue", "stateReason")} for s in mine]
        assert got == want, f"alarm history of {name!r} for SetAlarmState {state}: {got!r}"

    _eventually(ctx, _HISTORY_CAP_S, probe)


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
