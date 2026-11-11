"""deploy-logs-log-group-rename-collision-blocks-replacement-rolls-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-log-group-rename-collision-blocks-replacement-rolls-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

# The request token in a resource-handler failure reason differs per request; it alone is masked.
_TOKEN = re.compile(r"\(RequestToken: [^,]*, ")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Renaming (a create-only change) a log group onto a name that already exists fails the
    replacement's create step and rolls back, leaving the original log group untouched; the
    same rename onto a free name succeeds and replaces it.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    name_a = ctx.unique_name("sim2real-behav-cfnrepl-logsneg-a-")
    collision_name = ctx.unique_name("sim2real-behav-cfnrepl-logsneg-taken-")
    name_c = ctx.unique_name("sim2real-behav-cfnrepl-logsneg-c-")
    stack_name = ctx.unique_name("sim2real-behav-cfnrepl-logsneg-")

    stack_id = _create(ctx, cfn, stack_name, _template(name_a))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", (
        f"create ended {_stack(cfn, stack_id)!r}"
    )
    group_a_before = _log_group(logs, name_a)
    assert group_a_before is not None, f"log group {name_a!r} must exist after create"

    # Out of band: occupy the name the replacement is about to try to create.
    logs.create_log_group(logGroupName=collision_name, tags={_TAGS[0]["Key"]: _TAGS[0]["Value"]})
    ctx.on_cleanup(_teardown(
        lambda: logs.delete_log_group(logGroupName=collision_name), "ResourceNotFoundException",
    ))

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(collision_name))
    status = _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"renaming onto a taken name must roll back, got {status!r}: {_stack(cfn, stack_id)!r}"
    )

    rows = [
        (status, _TOKEN.sub("(RequestToken: <token>, ", reason or ""), physical)
        for status, reason, physical in _rows_for(
            _events(cfn, stack_id)[before:], "Group", "PhysicalResourceId"
        )
    ]
    failed_reason = (
        f"Resource handler returned message: \"Resource of type 'AWS::Logs::LogGroup' with "
        f"identifier '{{\"/properties/LogGroupName\":\"{collision_name}\"}}' already exists.\" "
        f"(RequestToken: <token>, HandlerErrorCode: AlreadyExists)"
    )
    assert _in_order(rows, [
        ("UPDATE_IN_PROGRESS",
         "Requested update requires the creation of a new physical resource; hence creating one.",
         name_a),
        ("UPDATE_FAILED", failed_reason, name_a),
        ("UPDATE_COMPLETE", None, name_a),
    ]), (
        f"Group must report the replacement, fail it with the AlreadyExists reason and roll back "
        f"to the original id, in that order: {rows!r}"
    )
    original_deletes = [r for r in rows if r[0].startswith("DELETE_") and r[2] == name_a]
    assert original_deletes == [], f"the rollback never deletes the original: {original_deletes!r}"

    group_a_after = _log_group(logs, name_a)
    assert group_a_after is not None, (
        f"the original log group must survive a failed replacement, got {group_a_after!r}"
    )
    assert group_a_after["creationTime"] == group_a_before["creationTime"], (
        f"the original log group is the one CloudWatch Logs created first: creationTime "
        f"{group_a_before['creationTime']!r} -> {group_a_after['creationTime']!r}"
    )

    # Positive control: the same rename onto a free name succeeds and replaces it.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(name_c))
    status = _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert status == "UPDATE_COMPLETE", f"the unblocked rename must succeed, got {status!r}"

    group_c = _log_group(logs, name_c)
    assert group_c is not None, f"log group {name_c!r} must exist after the replacement"
    group_a_gone = _log_group(logs, name_a)
    assert group_a_gone is None, (
        f"the successful rename must remove the old log group, got {group_a_gone!r}"
    )


def _template(group_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Group": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": group_name}}},
    })


def _log_group(logs, name: str) -> dict | None:
    """The log group's own description by exact name, or None if it does not exist."""
    matches = [
        g
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
        for g in page["logGroups"]
        if g["logGroupName"] == name
    ]
    return matches[0] if matches else None


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows_for(events: list[dict], logical_id: str, *keys: str) -> list[tuple]:
    """``(ResourceStatus, ResourceStatusReason, *keys)`` for every event on ``logical_id``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), *(e.get(k) for k in keys))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every ``wanted`` row occurs in ``rows`` in that order; a None field matches any."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row)) for row in remaining)
        for want in wanted
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
