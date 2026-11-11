"""rollback-state-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-state-transition"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A failed update/create can be rolled back or cancelled, moving the stack through
    *_ROLLBACK_IN_PROGRESS to a terminal rollback state visible in ListStacks."""
    cfn = ctx.client("cloudformation")

    rollback_final_status, rollback_stack_name = _check_rollback_stack(ctx, cfn)
    assert rollback_final_status == "ROLLBACK_COMPLETE", (
        f"RollbackStack on a DisableRollback=True CREATE_FAILED stack should reach "
        f"ROLLBACK_COMPLETE, got {rollback_final_status}"
    )
    rollback_listed = cfn.list_stacks(StackStatusFilter=["ROLLBACK_COMPLETE"])["StackSummaries"]
    assert any(s["StackName"] == rollback_stack_name for s in rollback_listed), rollback_listed

    cancel_final_status, cancel_stack_name = _check_cancel_update_stack(ctx, cfn)
    assert cancel_final_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"CancelUpdateStack during UPDATE_IN_PROGRESS should reach UPDATE_ROLLBACK_COMPLETE, "
        f"got {cancel_final_status}"
    )
    cancel_listed = cfn.list_stacks(StackStatusFilter=["UPDATE_ROLLBACK_COMPLETE"])["StackSummaries"]
    assert any(s["StackName"] == cancel_stack_name for s in cancel_listed), cancel_listed


def _check_rollback_stack(ctx, cfn):
    stack_name = ctx.unique_name("sim2real-rollback-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "10", "Count": "1"},
                },
            },
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template, DisableRollback=True)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))

    failed_status = _wait_stack_status(cfn, stack_name, {"CREATE_FAILED", "CREATE_COMPLETE"}, timeout_s=120)
    assert failed_status == "CREATE_FAILED", f"expected the unsignalled WaitCondition to fail creation, got {failed_status}"

    cfn.rollback_stack(StackName=stack_name)
    final_status = _wait_stack_status(
        cfn, stack_name, {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, timeout_s=180
    )
    assert final_status == "ROLLBACK_COMPLETE", final_status

    listed = cfn.list_stacks(StackStatusFilter=["ROLLBACK_COMPLETE"])["StackSummaries"]
    assert any(s["StackName"] == stack_name for s in listed), listed

    remaining = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    not_deleted = [r for r in remaining if r["ResourceStatus"] != "DELETE_COMPLETE"]
    assert not_deleted == [], (
        f"ROLLBACK_COMPLETE after a failed CREATE should leave every resource DELETE_COMPLETE, "
        f"got {not_deleted}"
    )
    return final_status, stack_name


def _check_cancel_update_stack(ctx, cfn):
    stack_name = ctx.unique_name("sim2real-cancelupd-")
    base_template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=base_template)
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    update_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic"},
                "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "120", "Count": "1"},
                },
            },
        }
    )
    cfn.update_stack(StackName=stack_name, TemplateBody=update_template)

    _wait_stack_status(cfn, stack_name, {"UPDATE_IN_PROGRESS"}, timeout_s=60)
    cfn.cancel_update_stack(StackName=stack_name)

    final_status = _wait_stack_status(
        cfn, stack_name, {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE"}, timeout_s=240
    )
    assert final_status == "UPDATE_ROLLBACK_COMPLETE", final_status

    listed = cfn.list_stacks(StackStatusFilter=["UPDATE_ROLLBACK_COMPLETE"])["StackSummaries"]
    assert any(s["StackName"] == stack_name for s in listed), listed

    resource_status = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    }
    assert set(resource_status) == {"Topic"}, (
        f"UPDATE_ROLLBACK_COMPLETE after CancelUpdateStack should revert the resource set to just "
        f"the pre-update Topic (Handle/Wait added by the cancelled update should disappear), "
        f"got {resource_status}"
    )
    assert resource_status["Topic"] == "CREATE_COMPLETE", (
        f"the untouched Topic should remain CREATE_COMPLETE after the cancelled update rolled "
        f"back, got {resource_status}"
    )
    return final_status, stack_name


def _safe_delete_stack(cfn, stack_name) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
