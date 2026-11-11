"""cfn-logs-log-stream-retained-replacement-keeps-events-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-log-stream-retained-replacement-keeps-events-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: An ingested event becomes readable within seconds; the cap only stops a hung poll.
_READ_CAP_S = 30.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Logs' refusal of a log stream that does not exist.
_NOT_FOUND = ("ResourceNotFoundException", "The specified log stream does not exist.")
_GROUP_NOT_FOUND = "ResourceNotFoundException"


def _template(group: str, stream: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Stream": {
                    "Type": "AWS::Logs::LogStream",
                    # Both properties are create-only: the type has no in-place update, and a
                    # LogStreamName change replaces the stream.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {"LogGroupName": group, "LogStreamName": stream},
                },
            },
            "Outputs": {"StreamName": {"Value": {"Ref": "Stream"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation log stream stores events; a LogStreamName change under Retain keeps both.

    The retained stream keeps its event past the stack delete, the stack's own stream answers
    ResourceNotFoundException. Every property is create-only, so there is no in-place step.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-logstream.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    group = "/" + ctx.unique_name("sim2real-cfnls-group-")
    first = ctx.unique_name("sim2real-cfnls-a-")
    second = ctx.unique_name("sim2real-cfnls-b-")
    stack_name = ctx.unique_name("sim2real-cfnls-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The log group belongs to the check, so the retained stream goes with it.
    ctx.on_cleanup(lambda: _delete_group(logs, group))
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Logs' view, and an event round trip
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(group, first), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == first, (
        f"the stream's physical id must be its LogStreamName {first!r}"
    )
    assert _outputs(stack) == {"StreamName": first}, f"Ref outputs {_outputs(stack)!r}"
    _eventually(ctx, _READ_CAP_S, lambda: _assert_streams(logs, group, [first]))
    kept = ctx.unique_name("kept-")
    _put(logs, group, first, kept)
    _eventually(ctx, _READ_CAP_S, lambda: _assert_events(logs, group, first, [kept]))

    # ---- 2. replacement under UpdateReplacePolicy Retain: a new stream, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(group, second), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == second, (
        f"the replacement's physical id must be its LogStreamName {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Stream"), first, second, "Stream"
    )
    assert _outputs(stack) == {"StreamName": second}, f"Ref after replacement {_outputs(stack)!r}"
    _eventually(ctx, _READ_CAP_S, lambda: _assert_streams(logs, group, sorted([first, second])))
    fresh = ctx.unique_name("fresh-")
    _put(logs, group, second, fresh)
    _eventually(ctx, _READ_CAP_S, lambda: _assert_events(logs, group, second, [fresh]))
    _assert_events(logs, group, first, [kept])

    # ---- 3. delete: Logs no longer knows the stack's stream; the retained one keeps its event
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: logs.get_log_events(logGroupName=group, logStreamName=second),
        _NOT_FOUND[0],
        f"log stream {second}",
    )
    assert got == _NOT_FOUND, f"GetLogEvents after the stack delete answered {got!r}"
    _assert_streams(logs, group, [first])
    _assert_events(logs, group, first, [kept])


def _put(logs, group: str, stream: str, message: str) -> None:
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
    )


def _assert_streams(logs, group: str, names: list[str]) -> None:
    pages = logs.get_paginator("describe_log_streams").paginate(logGroupName=group)
    got = sorted(s["logStreamName"] for page in pages for s in page["logStreams"])
    assert got == names, f"log streams of {group!r}: {got!r}, expected {names!r}"


def _assert_events(logs, group: str, stream: str, messages: list[str]) -> None:
    events = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    got = [e["message"] for e in events["events"]]
    assert got == messages, f"events of {group}/{stream}: {got!r}, expected {messages!r}"


def _delete_group(logs, group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _GROUP_NOT_FOUND:
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
