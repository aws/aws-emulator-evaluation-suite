"""change-set-hooks-reflect-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-hooks-reflect-status"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Hook invocation status for a change set is exposed by DescribeChangeSetHooks
    once the change set is created."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cshooks-")
    base_template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack(
        StackName=stack_name, TemplateBody=base_template, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    updated_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic"},
                "Queue": {"Type": "AWS::SQS::Queue"},
            },
        }
    )
    cs_name = ctx.unique_name("sim2real-cs-")
    cfn.create_change_set(
        StackName=stack_name, ChangeSetName=cs_name, ChangeSetType="UPDATE", TemplateBody=updated_template
    )
    ctx.on_cleanup(lambda: _safe_delete_change_set(cfn, stack_name, cs_name))

    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=cs_name),
        lambda r: r["Status"] in ("CREATE_COMPLETE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert described["Status"] == "CREATE_COMPLETE", described.get("StatusReason")

    hooks = cfn.describe_change_set_hooks(StackName=stack_name, ChangeSetName=cs_name)
    assert hooks["ChangeSetId"] == described["ChangeSetId"], hooks
    # Real AWS always runs hook planning to completion once the change set itself is
    # CREATE_COMPLETE, even with zero hook types registered/activated in the account -> the
    # terminal answer here is deterministically "PLANNED", not "any status the API happens to
    # model".
    assert hooks["Status"] == "PLANNED", hooks
    assert isinstance(hooks["Hooks"], list)
    # no hooks are registered in this account -> nothing should have been invoked yet
    assert hooks["Hooks"] == [], hooks


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _safe_delete_change_set(cfn, stack_name, cs_name) -> None:
    try:
        cfn.delete_change_set(StackName=stack_name, ChangeSetName=cs_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses}, last={status}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
