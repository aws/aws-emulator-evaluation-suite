"""deploy-log-group-cfn-invalid-retention-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-log-group-cfn-invalid-retention-rejected"
GROUP = "deploy"
SERVICES = ["logs"]

_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "CREATE_FAILED",
}


@tags("axis:rejection", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Logs::LogGroup with RetentionInDays=4 (not an allowed value) fails to
    deploy and leaves no log group, while the same template with a valid value deploys and
    is usable."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    bad_group_name = ctx.unique_name("sim2real-behav-logs-badret-group-")
    bad_stack_name = ctx.unique_name("sim2real-behav-logs-badret-stack-")
    good_group_name = ctx.unique_name("sim2real-behav-logs-goodret-group-")
    good_stack_name = ctx.unique_name("sim2real-behav-logs-goodret-stack-")

    bad_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                # 4 is not in the documented allowed RetentionInDays enum (1,3,5,7,14,30,...).
                "Properties": {"LogGroupName": bad_group_name, "RetentionInDays": 4},
            }
        },
    }
    good_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": good_group_name, "RetentionInDays": 3},
            }
        },
    }

    # --- broken: invalid RetentionInDays must be rejected, and the log group must never exist.
    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps(bad_template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_name))
    bad_status = _wait_stack_terminal(cfn, bad_stack_name, timeout_s=300, interval_s=10)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack with invalid RetentionInDays=4 should roll back, got {bad_status}"
    )
    rollback_reasons = [
        e.get("ResourceStatusReason")
        for e in cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
        if e["LogicalResourceId"] == bad_stack_name and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
    ]
    assert rollback_reasons == [
        "The following resource(s) failed to create: [LogGroup]. Rollback requested by user."
    ], f"unexpected ROLLBACK_IN_PROGRESS reason(s): {rollback_reasons!r}"
    # message varies: the LogGroup CREATE_FAILED reason embeds per-call request ids and a
    # request token, so only the stack-level rollback reason is asserted exactly.
    existing = logs.describe_log_groups(logGroupNamePrefix=bad_group_name)["logGroups"]
    assert existing == [], "log group from the rolled-back stack must not exist"

    # --- positive control: an identical template with a valid RetentionInDays succeeds.
    cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=json.dumps(good_template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_name))
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(logs, good_group_name))
    good_status = _wait_stack_terminal(cfn, good_stack_name, timeout_s=300, interval_s=10)
    assert good_status == "CREATE_COMPLETE", (
        f"stack with valid RetentionInDays=3 should succeed, got {good_status}"
    )
    good_groups = logs.describe_log_groups(logGroupNamePrefix=good_group_name)["logGroups"]
    assert len(good_groups) == 1, (
        f"expected exactly one log group named {good_group_name!r}, got {good_groups}"
    )
    assert good_groups[0]["retentionInDays"] == 3, (
        f"expected retentionInDays=3, got {good_groups[0].get('retentionInDays')}"
    )

    # Confirm in CloudWatch Logs itself, not just the stack status, that the group is gone.
    cfn.delete_stack(StackName=good_stack_name)
    _wait_stack_deleted(cfn, good_stack_name, timeout_s=300, interval_s=10)
    after_delete = logs.describe_log_groups(logGroupNamePrefix=good_group_name)["logGroups"]
    assert after_delete == [], f"log group {good_group_name!r} still exists after stack delete: {after_delete}"
    dead_code, dead_message = _error(
        lambda: logs.put_retention_policy(logGroupName=good_group_name, retentionInDays=3)
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted log group, got {dead_code}"
    )
    assert dead_message == "The specified log group does not exist.", (
        f"unexpected message mutating a deleted log group: {dead_message!r}"
    )


def _wait_stack_terminal(cfn: Any, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state, last seen {status}")


def _wait_stack_deleted(cfn: Any, stack_name: str, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status != "DELETE_IN_PROGRESS":
            raise AssertionError(f"stack {stack_name} left DELETE_IN_PROGRESS, got {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not delete within {timeout_s}s, last saw {status}")


def _error(fn: Any) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _delete_log_group_if_exists(logs: Any, group_name: str) -> None:
    """The stack delete normally removes the group first; only a leftover is deleted."""
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_stack(cfn: Any, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
