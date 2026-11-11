"""stack-policy-roundtrip-and-enforcement."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "stack-policy-roundtrip-and-enforcement"
GROUP = "server-side"
SERVICES = ["cloudformation"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStackPolicy round-trips the policy; a Deny on ProtectedQueue rolls back an update that
    succeeds without it, leaving both queues unchanged, and lifting the Deny lets it complete."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-stackpolicy-")

    template_v1 = _queue_template(30, 30)
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template_v1),
        Tags=[{"Key": "sim2real", "Value": "stack-policy-roundtrip-and-enforcement"}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack create failed: {status}"

    protected_url = _queue_url(cfn, stack_id, "ProtectedQueue")
    free_url = _queue_url(cfn, stack_id, "FreeQueue")

    # Positive control: with no policy, this same kind of update succeeds.
    template_v2 = _queue_template(45, 45)
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_v2))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"baseline update (no policy) must succeed, got {status}"
    assert _queue_timeout(sqs, protected_url) == "45", "baseline update must have applied to ProtectedQueue"
    assert _queue_timeout(sqs, free_url) == "45", "baseline update must have applied to FreeQueue"

    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "LogicalResourceId/ProtectedQueue"},
        ]
    }
    cfn.set_stack_policy(StackName=stack_id, StackPolicyBody=json.dumps(policy))

    # --- round-trip ---
    got_body = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert got_body == policy, f"stack policy round-trip mismatch: {got_body} != {policy}"

    # --- enforcement: the identical kind of update now tries to change both queues; the
    # protected one must block it (and the whole stack must roll back, taking FreeQueue with it).
    template_v3 = _queue_template(60, 60)
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_v3))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"expected stack policy to block update, got {status}"

    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    protected_failures = [
        e for e in events
        if e.get("LogicalResourceId") == "ProtectedQueue" and e.get("ResourceStatus") == "UPDATE_FAILED"
    ]
    assert protected_failures, "expected an UPDATE_FAILED event for the policy-protected resource"
    reason = (protected_failures[0].get("ResourceStatusReason") or "").lower()
    assert "policy" in reason, f"expected stack-policy denial reason, got: {reason!r}"

    assert _queue_timeout(sqs, protected_url) == "45", (
        "protected queue's VisibilityTimeout must be unchanged by the blocked update"
    )
    assert _queue_timeout(sqs, free_url) == "45", (
        "unprotected queue must have rolled back too, since the whole stack rolled back"
    )

    # Lift the Deny and replay the identical update; it must now succeed.
    cfn.set_stack_policy(
        StackName=stack_id,
        StackPolicyBody=json.dumps({"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}),
    )
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(template_v3))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"identical update must succeed once the Deny is lifted, got {status}"
    assert _queue_timeout(sqs, protected_url) == "60", "protected queue must update once its Deny is lifted"
    assert _queue_timeout(sqs, free_url) == "60", "unprotected queue must update too"



def _queue_template(protected_timeout: int, free_timeout: int) -> dict[str, Any]:
    return {
        "Resources": {
            "ProtectedQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": protected_timeout},
            },
            "FreeQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": free_timeout},
            },
        }
    }


def _queue_url(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _queue_timeout(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]


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
