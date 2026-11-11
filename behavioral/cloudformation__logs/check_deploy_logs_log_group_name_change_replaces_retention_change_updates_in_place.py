"""deploy-logs-log-group-name-change-replaces-retention-change-updates-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-log-group-name-change-replaces-retention-change-updates-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

#: A stack or change-set transition here takes seconds to a few minutes; the bound only stops a
#: hung poll.
_DEADLINE_S = 600.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A change set classifies a LogGroupName change Replacement=True and a RetentionInDays
    change Replacement=False; executing replaces the first log group (new id, old gone from
    CloudWatch Logs, new carries the new name) and updates the second in place.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    name_a = ctx.unique_name("sim2real-behav-cfnrepl-logs-a-")
    name_b = ctx.unique_name("sim2real-behav-cfnrepl-logs-b-")
    stable_name = ctx.unique_name("sim2real-behav-cfnrepl-logs-mod-")
    stack_name = ctx.unique_name("sim2real-behav-cfnrepl-logs-")

    stack_id = _create(ctx, cfn, stack_name, _template(name_a, stable_name, 1))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", (
        f"create ended {_stack(cfn, stack_id)!r}"
    )

    group_a = _log_group(logs, name_a)
    assert group_a is not None, f"log group {name_a!r} must exist after create"
    group_mod_before = _log_group(logs, stable_name)
    assert group_mod_before is not None and group_mod_before["retentionInDays"] == 1, group_mod_before

    before = len(_events(cfn, stack_id))

    cs_name = ctx.unique_name("sim2real-behav-cfnrepl-logs-cs-")
    cfn.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name,
        TemplateBody=_template(name_b, stable_name, 3),
    )
    ctx.on_cleanup(_teardown(
        lambda: cfn.delete_change_set(StackName=stack_id, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cfn, stack_id, cs_name, timeout_s=_cap(ctx, 300.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = {c["ResourceChange"]["LogicalResourceId"]: c["ResourceChange"] for c in cs["Changes"]}
    assert set(changes) == {"Replaced", "Modified"}, (
        f"the change set must report both touched resources, got {sorted(changes)}"
    )

    repl = changes["Replaced"]
    assert repl["Action"] == "Modify", f"expected Action=Modify, got {repl['Action']!r}"
    assert repl.get("Replacement") == "True", (
        f"changing the create-only LogGroupName must classify Replacement=True, got "
        f"{repl.get('Replacement')!r}"
    )
    repl_targets = {
        d["Target"]["Name"]: d["Target"] for d in repl.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert repl_targets.get("LogGroupName", {}).get("RequiresRecreation") == "Always", (
        f"LogGroupName must report RequiresRecreation=Always, got {repl_targets!r}"
    )

    mod = changes["Modified"]
    assert mod["Action"] == "Modify", f"expected Action=Modify, got {mod['Action']!r}"
    assert mod.get("Replacement") == "False", (
        f"changing the mutable RetentionInDays must classify Replacement=False, got "
        f"{mod.get('Replacement')!r}"
    )
    mod_targets = {
        d["Target"]["Name"]: d["Target"] for d in mod.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert mod_targets.get("RetentionInDays", {}).get("RequiresRecreation") == "Never", (
        f"RetentionInDays must report RequiresRecreation=Never, got {mod_targets!r}"
    )

    # The change set's prediction must match what execution actually does.
    cfn.execute_change_set(StackName=stack_id, ChangeSetName=cs_name)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", (
        f"update ended {_stack(cfn, stack_id)!r}"
    )

    new_events = _events(cfn, stack_id)[before:]

    replaced_rows = _rows_for(new_events, "Replaced", "PhysicalResourceId")
    assert _in_order(replaced_rows, [
        ("UPDATE_IN_PROGRESS",
         "Requested update requires the creation of a new physical resource; hence creating one.",
         None),
        ("UPDATE_COMPLETE", None, name_b),
        ("DELETE_COMPLETE", None, name_a),
    ]), (
        f"Replaced must report the replacement, complete as {name_b!r} and delete {name_a!r}, "
        f"in that order: {replaced_rows!r}"
    )

    modified_rows = _rows_for(new_events, "Modified", "PhysicalResourceId")
    assert _in_order(modified_rows, [("UPDATE_COMPLETE", None, stable_name)]), (
        f"Modified must complete its update as {stable_name!r}: {modified_rows!r}"
    )
    modified_deletes = [r for r in modified_rows if r[0].startswith("DELETE_")]
    assert modified_deletes == [], f"an in-place update deletes nothing: {modified_deletes!r}"

    resource_b = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Replaced")[
        "StackResourceDetail"
    ]
    assert resource_b["PhysicalResourceId"] == name_b, resource_b

    group_b = _log_group(logs, name_b)
    assert group_b is not None, f"log group {name_b!r} must exist after the replacement"

    group_a_after = _log_group(logs, name_a)
    assert group_a_after is None, (
        f"the replaced log group {name_a!r} must be gone from CloudWatch Logs, got {group_a_after!r}"
    )

    group_mod_after = _log_group(logs, stable_name)
    assert group_mod_after is not None and group_mod_after["logGroupName"] == stable_name, group_mod_after
    assert group_mod_after["retentionInDays"] == 3, (
        f"the in-place update must have applied the new RetentionInDays, got {group_mod_after!r}"
    )
    assert group_mod_after["creationTime"] == group_mod_before["creationTime"], (
        f"an in-place update keeps the log group CloudWatch Logs created: creationTime "
        f"{group_mod_before['creationTime']!r} -> {group_mod_after['creationTime']!r}"
    )


def _template(replaced_name: str, modified_name: str, modified_retention_days: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            # LogGroupName is create-only for AWS::Logs::LogGroup -> changing it replaces.
            "Replaced": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": replaced_name},
            },
            # RetentionInDays is updatable in place -> changing it modifies, and the
            # LogGroupName is deliberately held constant so this resource is never replaced.
            "Modified": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": modified_name, "RetentionInDays": modified_retention_days},
            },
        },
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


def _wait_change_set(cfn, stack_id: str, cs_name: str, *, timeout_s: float = 300.0) -> dict:
    """Poll DescribeChangeSet until Status is terminal; return the response."""
    return _poll(
        lambda: cfn.describe_change_set(StackName=stack_id, ChangeSetName=cs_name),
        lambda r: r["Status"] in ("CREATE_COMPLETE", "FAILED"),
        timeout_s=timeout_s, what=f"change set {cs_name}",
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
