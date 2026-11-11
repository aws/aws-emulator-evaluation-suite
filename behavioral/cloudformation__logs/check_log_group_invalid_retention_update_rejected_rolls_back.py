"""log-group-invalid-retention-update-rejected-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-group-invalid-retention-update-rejected-rolls-back"
GROUP = "stack_update"
SERVICES = ["cloudformation", "logs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_VALID_RETENTIONS = (14, 30)
_INVALID_RETENTION = 45


def _template(name: str, retention_days: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Target": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": name, "RetentionInDays": retention_days},
            },
        },
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A valid RetentionInDays update succeeds (the positive control); the identical update
    shape carrying an unsupported value is refused via rollback, with the pre-update retention
    left exactly as it was and the log group itself untouched."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group_name = ctx.unique_name("sim2real-xsvc-lgret-")
    stack = ctx.unique_name("sim2real-xsvc-lgret-stack-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    cfn.create_stack(
        StackName=stack, TemplateBody=_template(group_name, _VALID_RETENTIONS[0])
    )
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended in {status!r}, expected CREATE_COMPLETE"
    assert _retention(logs, group_name) == _VALID_RETENTIONS[0], (
        f"log group {group_name!r} should start at {_VALID_RETENTIONS[0]} days retention"
    )
    physical_before = _physical_id(cfn, stack, "Target")

    # --- positive control: a valid RetentionInDays change succeeds -----------------------------
    cfn.update_stack(StackName=stack, TemplateBody=_template(group_name, _VALID_RETENTIONS[1]))
    status = _wait_terminal(cfn, stack)
    assert status == "UPDATE_COMPLETE", (
        f"positive control: valid retention update ended in {status!r}, expected UPDATE_COMPLETE"
    )
    assert _retention(logs, group_name) == _VALID_RETENTIONS[1], (
        f"log group {group_name!r} should now report {_VALID_RETENTIONS[1]} days retention"
    )

    # --- break exactly one thing: an unsupported RetentionInDays value --------------------------
    # CloudFormation only warns on this value at schema validation; the CloudWatch Logs backend
    # itself refuses it, so the update fails mid-flight and rolls back.
    cfn.update_stack(StackName=stack, TemplateBody=_template(group_name, _INVALID_RETENTION))
    status = _wait_terminal(cfn, stack, timeout_s=600.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update carrying an unsupported RetentionInDays must be refused via the "
        f"accepted-then-rolled-back arm, got {status!r}"
    )
    reason = _resource_failure_reason(cfn, stack, "Target")
    assert "Invalid retention value" in reason, (
        f"expected the CloudWatch Logs backend's own refusal message, got {reason!r}"
    )
    assert "90" in reason and "3653" in reason, (
        f"expected the refusal to enumerate the valid retention values, got {reason!r}"
    )

    # --- effect absent: retention and physical id are exactly what they were before the break --
    assert _retention(logs, group_name) == _VALID_RETENTIONS[1], (
        f"log group {group_name!r} retention must be rolled back to {_VALID_RETENTIONS[1]} days, "
        f"got {_retention(logs, group_name)}"
    )
    physical_after = _physical_id(cfn, stack, "Target")
    assert physical_after == physical_before, (
        f"RetentionInDays is mutable, not replacing; physical id must stay {physical_before!r}, "
        f"got {physical_after!r}"
    )


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _retention(logs, group_name: str) -> int | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group_name):
        for g in page["logGroups"]:
            if g["logGroupName"] == group_name:
                return g.get("retentionInDays")
    raise AssertionError(f"log group {group_name!r} not found")


def _resource_failure_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The *_FAILED event's own reason for one logical id -- the specific cause, not the
    stack-level rollback event's generic 'resource(s) failed to update' summary."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if (
                event.get("LogicalResourceId") == logical_id
                and event.get("ResourceStatus", "").endswith("_FAILED")
                and event.get("ResourceStatusReason")
            ):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no *_FAILED event with a reason found for logical id {logical_id!r}")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
