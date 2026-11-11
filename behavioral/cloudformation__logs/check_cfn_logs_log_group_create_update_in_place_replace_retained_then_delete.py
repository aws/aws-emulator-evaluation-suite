"""cfn-logs-log-group-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-log-group-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: An ingested event becomes readable within seconds; the bound only stops a hung poll.
_EVENTS_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_NOT_FOUND = ("ResourceNotFoundException", "The specified log group does not exist.")


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
    """An AWS::Logs::LogGroup survives create, in-place update, retained replacement and delete.

    Logs reads back the templated retention and stores events; a RetentionInDays change keeps the
    group; a LogGroupName change under UpdateReplacePolicy Retain keeps the old group, events too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    stack_name = ctx.unique_name("sim2real-cfnreal-logs-")
    group_v1 = "/" + ctx.unique_name("sim2real-cfnreal-logs-a-")
    group_v2 = "/" + ctx.unique_name("sim2real-cfnreal-logs-b-")

    # The replaced group outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_group(logs, group_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, Logs view, behaviour -------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(group_v1, 7), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Group", group_v1)
    group = _group(logs, group_v1)
    assert group.get("retentionInDays") == 7, f"templated RetentionInDays 7, got {group!r}"
    first = _write_and_read(ctx, logs, group_v1, "first-event")
    created_at = group["creationTime"]

    # ---- 2. in-place update of the mutable RetentionInDays ----------------------------------
    rows = _update(ctx, cfn, stack_id, "Group", _template(group_v1, 14))
    _assert_updated_in_place(rows, group_v1)
    _assert_tracks(cfn, stack_id, "Group", group_v1)
    group = _group(logs, group_v1)
    assert group.get("retentionInDays") == 14, f"updated RetentionInDays 14, got {group!r}"
    assert group["creationTime"] == created_at, (
        f"an in-place update keeps the group: creationTime {created_at!r} -> {group!r}"
    )
    assert _messages(logs, group_v1, first) == ["first-event"], (
        "an in-place update keeps the group's events"
    )

    # ---- 3. LogGroupName forces replacement; UpdateReplacePolicy Retain keeps the old one ----
    rows = _update(ctx, cfn, stack_id, "Group", _template(group_v2, 14))
    _assert_replaced_and_retained(rows, group_v1, group_v2)
    _assert_tracks(cfn, stack_id, "Group", group_v2)
    new = _group(logs, group_v2)
    assert new.get("retentionInDays") == 14, f"the replacement carries retention 14, got {new!r}"
    _write_and_read(ctx, logs, group_v2, "second-event")
    old = _group(logs, group_v1)
    assert old.get("retentionInDays") == 14, f"the retained group keeps its retention: {old!r}"
    assert _messages(logs, group_v1, first) == ["first-event"], (
        f"the retained group {group_v1!r} must keep its events"
    )

    # ---- 4. DeleteStack: the group it owns is gone ------------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _error(lambda: logs.describe_log_streams(logGroupName=group_v2))
    assert got == _NOT_FOUND, f"DescribeLogStreams after DeleteStack: {got!r}, not {_NOT_FOUND!r}"
    assert _group(logs, group_v1).get("retentionInDays") == 14, (
        "the retained group must survive DeleteStack"
    )


def _template(name: str, retention_days: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Group": {
                    "Type": "AWS::Logs::LogGroup",
                    # LogGroupName is create-only, so a new name replaces the group.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {"LogGroupName": name, "RetentionInDays": retention_days},
                },
            },
        }
    )


def _group(logs, name: str) -> dict:
    """The one log group named exactly name (DescribeLogGroups matches by prefix)."""
    found = [
        g
        for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if g["logGroupName"] == name
    ]
    assert len(found) == 1, f"Logs must hold exactly one group {name!r}, got {found!r}"
    return found[0]


def _write_and_read(ctx, logs, group: str, message: str) -> str:
    """Behaviour: create a stream in group, put one event and read it back; return the stream."""
    stream = "probe"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
    )
    got = _poll(
        ctx,
        lambda: _messages(logs, group, stream),
        lambda m: m != [],
        cap_s=_EVENTS_S,
        what=f"the event in {group!r}",
    )
    assert got == [message], f"the group must serve back exactly the event written, got {got!r}"
    return stream


def _messages(logs, group: str, stream: str) -> list[str]:
    events = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    return [e["message"] for e in events["events"]]


def _delete_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
