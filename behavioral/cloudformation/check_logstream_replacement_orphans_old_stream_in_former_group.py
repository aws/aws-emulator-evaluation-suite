"""logstream-replacement-orphans-old-stream-in-former-group."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logstream-replacement-orphans-old-stream-in-former-group"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_STREAM_NAME = "application"


def _template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"GroupName": {"Type": "String"}},
        "Resources": {
            "Stream": {"Type": "AWS::Logs::LogStream",
                       "Properties": {"LogGroupName": {"Ref": "GroupName"},
                                      "LogStreamName": _STREAM_NAME}},
        },
        "Outputs": {"StreamRef": {"Value": {"Ref": "Stream"}}},
    })


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Moving a named LogStream to another LogGroupName replaces it; CloudFormation reports the old
    stream DELETE_COMPLETE, yet it stays readable with its content in the former group, and
    DeleteStack removes only the tracked stream. Unrelated sibling streams are untouched throughout.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    first_group = ctx.unique_name("sim2real-behav-ls-move-first-")
    second_group = ctx.unique_name("sim2real-behav-ls-move-second-")
    for g in (first_group, second_group):
        logs.create_log_group(logGroupName=g)
        ctx.on_cleanup(lambda g=g: _delete_log_group_if_present(logs, g))
        logs.create_log_stream(logGroupName=g, logStreamName="unrelated")

    stack = ctx.unique_name("sim2real-behav-ls-move-stack-")
    cfn.create_stack(
        StackName=stack, TemplateBody=_template(),
        Parameters=[{"ParameterKey": "GroupName", "ParameterValue": first_group}],
        OnFailure="ROLLBACK", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id, _budget_s(ctx, 300.0), ctx=ctx)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}, expected CREATE_COMPLETE"

    physical_id = _physical_id(cfn, stack_id, "Stream")
    assert physical_id == _STREAM_NAME, f"physical id is {physical_id!r}, expected {_STREAM_NAME!r}"
    assert _stream_names(logs, first_group) == {_STREAM_NAME, "unrelated"}, (
        f"first group streams are {_stream_names(logs, first_group)!r}"
    )
    _assert_writable(logs, first_group, _STREAM_NAME, "before move", _budget_s(ctx, 60.0),
                     ctx=ctx)

    cfn.update_stack(
        StackName=stack_id, UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "GroupName", "ParameterValue": second_group}],
    )
    status = _wait_stack(cfn, stack_id, _budget_s(ctx, 300.0), ctx=ctx)
    assert status == "UPDATE_COMPLETE", f"move update ended {status!r}, expected UPDATE_COMPLETE"

    events = _stack_events(cfn, stack_id)
    old_deletes = [e for e in events
                   if e["LogicalResourceId"] == "Stream" and e["ResourceStatus"] == "DELETE_COMPLETE"]
    assert old_deletes, (
        "no Stream DELETE_COMPLETE event for the replaced resource; sequence was "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r}"
    )

    moved_id = _physical_id(cfn, stack_id, "Stream")
    assert moved_id == _STREAM_NAME, f"physical id after the move is {moved_id!r}"
    assert _stream_names(logs, second_group) == {_STREAM_NAME, "unrelated"}, (
        f"second group streams after the move are {_stream_names(logs, second_group)!r}"
    )
    _assert_writable(logs, second_group, _STREAM_NAME, "after move", _budget_s(ctx, 60.0),
                     ctx=ctx)

    # Several reads apart, so the orphan's presence is not one stale view of a pending delete.
    for _ in range(4):
        orphan_present = _stream_names(logs, first_group)
        assert orphan_present == {_STREAM_NAME, "unrelated"}, (
            f"first group streams after the move are {orphan_present!r}; real AWS leaves the "
            "superseded stream orphaned here despite CloudFormation's own DELETE_COMPLETE event"
        )
        time.sleep(2.0)
    orphan_events = logs.get_log_events(logGroupName=first_group, logStreamName=_STREAM_NAME,
                                        startFromHead=True)["events"]
    assert any(e["message"] == "sim2real before move" for e in orphan_events), (
        f"the orphaned stream lost its pre-move content; events were {orphan_events!r}"
    )

    cfn.delete_stack(StackName=stack_id)
    del_status = _wait_stack(cfn, stack_id, _budget_s(ctx, 300.0), ctx=ctx)
    assert del_status == "DELETE_COMPLETE", f"stack delete ended {del_status!r}, expected DELETE_COMPLETE"
    assert _stream_names(logs, first_group) == {_STREAM_NAME, "unrelated"}, (
        f"first group streams after DeleteStack are {_stream_names(logs, first_group)!r}; "
        "the stack never tracked this group's stream, so its own delete cannot touch it"
    )
    second_after = _poll_stream_names(logs, second_group, {"unrelated"},
                                      timeout_s=_budget_s(ctx, 60.0), interval_s=1.0)
    if second_after != {"unrelated"} and _budget_spent(ctx):
        raise TimeoutError(f"second group {second_group} listing only the unrelated stream: "
                           "the run budget ended first; not graded")
    assert second_after == {"unrelated"}, (
        f"second group streams after DeleteStack are {second_after!r}; the tracked stream must "
        "be deleted, the unrelated one must remain"
    )


def _stream_names(logs, group):
    names = set()
    for page in logs.get_paginator("describe_log_streams").paginate(logGroupName=group):
        for s in page["logStreams"]:
            names.add(s["logStreamName"])
    return names


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_stream_names(logs, group, expected, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    names = set()
    while time.monotonic() < deadline:
        names = _stream_names(logs, group)
        if names == expected:
            return names
        time.sleep(interval_s)
    return names


def _assert_writable(logs, group, stream, when, timeout_s=60.0, ctx=None):
    now_ms = int(time.time() * 1000)
    message = f"sim2real {when}"
    put = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": message}],
    )
    assert "rejectedLogEventsInfo" not in put, f"PutLogEvents ({when}) partially rejected: {put!r}"

    deadline = time.monotonic() + timeout_s
    events = []
    while time.monotonic() < deadline:
        events = logs.get_log_events(logGroupName=group, logStreamName=stream,
                                     startFromHead=True)["events"]
        if any(e["message"] == message for e in events):
            return
        time.sleep(1.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"the just-written event readable from {group}/{stream} ({when}): "
                           "the run budget ended first; not graded")
    raise AssertionError(
        f"the just-written event is not readable back from {group}/{stream} ({when}) after {timeout_s:.0f}s; "
        f"events were {events!r}"
    )


def _wait_stack(cfn, stack_id, timeout_s=300.0, interval_s=1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_id} terminal: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_id} did not reach terminal status within {timeout_s}s (last={status})")


def _stack_events(cfn, stack_id):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return sorted(out, key=lambda e: e["Timestamp"])


def _physical_id(cfn, stack_id, logical_id):
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _delete_log_group_if_present(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"log group {name}: {exc}") from exc


def _delete_stack(cfn, stack_id):
    try:
        cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                if not (
                    err.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in err.response["Error"].get("Message", "")
                ):
                    raise
                return
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(f"stack {stack_id} DELETE_FAILED")
            time.sleep(2.0)
        raise RuntimeError(f"stack {stack_id} still deleting after 300s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
