"""stack-policy-delete-protected-resource-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "stack-policy-delete-protected-resource-rejected"
GROUP = "server-side"
SERVICES = ["cloudformation"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack policy Deny on a queue blocks its replacement (UPDATE_ROLLBACK_COMPLETE, a policy
    reason, queue unreplaced); once the Deny is lifted the identical update replaces it.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-stackpolicy-del-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(None)),
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    create_status = _wait_stack_terminal(cfn, stack_id)
    assert create_status == "CREATE_COMPLETE", f"stack create failed: {create_status}"

    protected_url = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="ProtectedQueue"
    )["StackResourceDetail"]["PhysicalResourceId"]

    deny_policy = json.dumps({
        "Statement": [
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "LogicalResourceId/ProtectedQueue"},
        ]
    })
    cfn.set_stack_policy(StackName=stack_id, StackPolicyBody=deny_policy)

    # Changing the immutable QueueName forces a replacement under the same logical id. Removing the
    # resource instead would fail validation with "Unknown logical id": the policy reference is
    # resolved against the new template.
    replacement_name = ctx.unique_name("sim2real-protq-")
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(_template(replacement_name)))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"expected stack policy to block resource replacement, got {status}"

    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    protected_failures = [
        e for e in events
        if e.get("LogicalResourceId") == "ProtectedQueue" and e.get("ResourceStatus") == "UPDATE_FAILED"
    ]
    assert protected_failures, "expected an UPDATE_FAILED event for the policy-protected resource"
    reason = (protected_failures[0].get("ResourceStatusReason") or "").lower()
    assert "policy" in reason, f"expected a stack-policy denial reason, got: {reason!r}"

    attrs = sqs.get_queue_attributes(QueueUrl=protected_url, AttributeNames=["QueueArn"])
    assert attrs["Attributes"]["QueueArn"], "protected queue should not have been deleted"

    detail = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="ProtectedQueue")[
        "StackResourceDetail"
    ]
    assert detail["PhysicalResourceId"] == protected_url, (
        f"protected queue should not have been replaced, got new physical id {detail['PhysicalResourceId']!r}"
    )

    allow_policy = json.dumps({
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    })
    cfn.set_stack_policy(StackName=stack_id, StackPolicyBody=allow_policy)
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(_template(replacement_name)))
    restored_status = _wait_stack_terminal(cfn, stack_id)
    assert restored_status == "UPDATE_COMPLETE", (
        f"expected the identical update to succeed once the policy allows it, got {restored_status}"
    )

    replaced = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="ProtectedQueue")[
        "StackResourceDetail"
    ]
    assert replaced["PhysicalResourceId"] != protected_url, (
        "protected queue should now have been replaced once the policy allows it"
    )


def _template(protected_queue_name: str | None) -> dict[str, Any]:
    resources: dict[str, Any] = {
        "FreeQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
    }
    protected_props: dict[str, Any] = {"VisibilityTimeout": 30}
    if protected_queue_name:
        protected_props["QueueName"] = protected_queue_name
    resources["ProtectedQueue"] = {"Type": "AWS::SQS::Queue", "Properties": protected_props}
    return {"Resources": resources}


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
