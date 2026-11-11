"""stack-refactor-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-refactor-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack refactor moves CREATE_IN_PROGRESS->CREATE_COMPLETE, its actions are
    listable, and executing it (AVAILABLE->EXECUTE_COMPLETE) renames a logical
    resource ID in place without recreating the underlying physical resource."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-refactor-")
    old_logical_id = "TopicOld"
    new_logical_id = "TopicNew"

    template_old = _sns_template(old_logical_id)
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template_old),
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_stack(cfn, stack_name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack['StackStatus']}"

    physical_id_before = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=old_logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]

    template_new = _sns_template(new_logical_id)
    try:
        refactor_id = cfn.create_stack_refactor(
            StackDefinitions=[{"StackName": stack_name, "TemplateBody": json.dumps(template_new)}],
            ResourceMappings=[
                {
                    "Source": {"StackName": stack_name, "LogicalResourceId": old_logical_id},
                    "Destination": {"StackName": stack_name, "LogicalResourceId": new_logical_id},
                }
            ],
        )["StackRefactorId"]
    except ClientError as exc:
        raise AssertionError(f"CreateStackRefactor rejected the refactor request: {exc}") from exc

    described = _poll_until(
        lambda: cfn.describe_stack_refactor(StackRefactorId=refactor_id),
        lambda d: d["Status"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    if described["Status"] != "CREATE_COMPLETE":
        raise AssertionError(f"stack refactor CREATE ended in {described['Status']}: {described.get('StatusReason')}")
    assert described["ExecutionStatus"] == "AVAILABLE", (
        f"expected ExecutionStatus AVAILABLE once CREATE_COMPLETE, got {described['ExecutionStatus']}"
    )

    refactor_ids = {r["StackRefactorId"] for r in cfn.list_stack_refactors()["StackRefactorSummaries"]}
    assert refactor_id in refactor_ids, f"{refactor_id} missing from ListStackRefactors: {refactor_ids}"

    actions = cfn.list_stack_refactor_actions(StackRefactorId=refactor_id)["StackRefactorActions"]
    move_actions = [a for a in actions if a.get("Entity") == "RESOURCE" and a.get("Action") == "MOVE"]
    assert move_actions, f"expected a RESOURCE MOVE action for the rename, got {actions}"
    mapping = move_actions[0]["ResourceMapping"]
    assert mapping["Source"]["LogicalResourceId"] == old_logical_id, mapping
    assert mapping["Destination"]["LogicalResourceId"] == new_logical_id, mapping

    cfn.execute_stack_refactor(StackRefactorId=refactor_id)
    executed = _poll_until(
        lambda: cfn.describe_stack_refactor(StackRefactorId=refactor_id),
        lambda d: d["ExecutionStatus"] in ("EXECUTE_COMPLETE", "EXECUTE_FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert executed["ExecutionStatus"] == "EXECUTE_COMPLETE", executed.get("ExecutionStatusReason")

    # The resource should now live under the new logical ID with the SAME physical
    # resource -- a refactor renames in place, it doesn't replace.
    physical_id_after = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=new_logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id_after == physical_id_before, (
        f"refactor should rename in place; expected physical id {physical_id_before}, got {physical_id_after}"
    )


def _sns_template(logical_id: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result}")
        time.sleep(interval_s)
        result = probe()
    return result


def _best_effort_delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
