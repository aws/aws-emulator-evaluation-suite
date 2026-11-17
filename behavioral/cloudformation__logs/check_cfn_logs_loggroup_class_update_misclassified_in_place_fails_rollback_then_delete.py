"""cfn-logs-loggroup-class-update-misclassified-in-place-fails-rollback-then-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-loggroup-class-update-misclassified-in-place-fails-rollback-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_DEADLINE_S = 600.0

_FAILED_REQUIRES_REPLACE = (
    "CloudFormation cannot update a stack when a custom-named resource requires replacing. "
    "Rename {name} and update the stack again."
)
_NOT_UPDATABLE = (
    'Resource handler returned message: "LogGroupClass is a Create-Only Property and cannot '
    'be updated" (RequestToken: <token>, HandlerErrorCode: NotUpdatable)'
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A LogGroupClass change set reports RequiresRecreation=Never, but CloudFormation can
    neither apply it in place nor roll it back, leaving the stack UPDATE_ROLLBACK_FAILED with
    the log group's class untouched; the stack still deletes afterward.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    name = ctx.unique_name("sim2real-behav-cfnlgc-")
    stack_name = ctx.unique_name("sim2real-behav-cfnlgc-stk-")

    stack_id = _create(ctx, cfn, stack_name, _template(name, "STANDARD"))
    assert _settle(cfn, stack_id) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    created = _log_group(logs, name)
    assert created is not None and created["logGroupClass"] == "STANDARD", (
        f"the template's LogGroupClass must be the live class, got {created!r}"
    )

    cs_name = ctx.unique_name("sim2real-behav-cfnlgc-cs-")
    cfn.create_change_set(
        StackName=stack_id, ChangeSetName=cs_name,
        TemplateBody=_template(name, "INFREQUENT_ACCESS"),
    )
    ctx.on_cleanup(_teardown(
        lambda: cfn.delete_change_set(StackName=stack_id, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cfn, stack_id, cs_name)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    assert len(cs["Changes"]) == 1, f"expected exactly one changed resource, got {cs['Changes']!r}"
    change = cs["Changes"][0]["ResourceChange"]
    assert change["Action"] == "Modify", f"expected Action=Modify, got {change['Action']!r}"
    assert change.get("Replacement") == "False", (
        f"the change set must classify a LogGroupClass-only change Replacement=False, got "
        f"{change.get('Replacement')!r}"
    )
    targets = {
        d["Target"]["Name"]: d["Target"] for d in change.get("Details", []) if d.get("Target", {}).get("Name")
    }
    assert targets.get("LogGroupClass", {}).get("RequiresRecreation") == "Never", (
        f"the change set must report LogGroupClass RequiresRecreation=Never, got {targets!r}"
    )

    # Executing the change the change set itself classified as a safe in-place update.
    cfn.execute_change_set(StackName=stack_id, ChangeSetName=cs_name)
    final_status = _settle(cfn, stack_id)
    assert final_status == "UPDATE_ROLLBACK_FAILED", (
        f"a LogGroupClass change the change set predicted as in-place must still fail to apply AND "
        f"fail to roll back cleanly; got {final_status!r}"
    )

    rows = [
        (e["ResourceStatus"], _masked(e.get("ResourceStatusReason") or ""))
        for e in _events(cfn, stack_id)
        if e["LogicalResourceId"] == "Group" and e["ResourceStatus"] in ("UPDATE_FAILED",)
    ]
    assert rows == [
        ("UPDATE_FAILED", _FAILED_REQUIRES_REPLACE.format(name=name)),
        ("UPDATE_FAILED", _NOT_UPDATABLE),
    ], f"the forward update and the rollback must fail with these two reasons, in order: {rows!r}"

    unchanged = _log_group(logs, name)
    assert unchanged is not None and unchanged["logGroupClass"] == "STANDARD", (
        f"with both the update and its rollback failed, the live class must still be STANDARD, "
        f"got {unchanged!r}"
    )
    assert unchanged["creationTime"] == created["creationTime"], (
        f"a failed in-place update attempt must not recreate the log group: creationTime "
        f"{created['creationTime']!r} -> {unchanged['creationTime']!r}"
    )

    # The stack still deletes even while stuck UPDATE_ROLLBACK_FAILED: DeleteStack removes the
    # log group regardless of the pending property mismatch.
    cfn.delete_stack(StackName=stack_id)
    delete_status = _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S))
    assert delete_status == "DELETE_COMPLETE", f"delete from UPDATE_ROLLBACK_FAILED ended {delete_status!r}"

    gone = _log_group(logs, name)
    assert gone is None, f"the deleted log group must be gone from CloudWatch Logs, got {gone!r}"


def _masked(text: str) -> str:
    """``text`` with only its per-call RequestToken replaced."""
    return re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)


def _template(name: str, log_group_class: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": name, "LogGroupClass": log_group_class},
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
    if status not in ("CREATE_IN_PROGRESS", "DELETE_COMPLETE"):
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
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
