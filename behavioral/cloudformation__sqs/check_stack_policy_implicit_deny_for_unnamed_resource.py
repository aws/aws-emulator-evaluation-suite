"""stack-policy-implicit-deny-for-unnamed-resource."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stack-policy-implicit-deny-for-unnamed-resource"
GROUP = "server-side"
SERVICES = ["cloudformation", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _queue_template(free_timeout: int, protected_timeout: int) -> str:
    return json.dumps({
        "Resources": {
            "FreeQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": free_timeout},
            },
            "ProtectedQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"VisibilityTimeout": protected_timeout},
            },
        }
    })


def _queue_url(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _queue_timeout(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]


def _wait_queue_timeout(ctx, sqs, queue_url: str, expected: str, cap_s: float = 90.0) -> None:
    """Poll GetQueueAttributes until VisibilityTimeout reads ``expected``; SQS attribute changes
    can take up to 60 s to propagate."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    got = None
    while time.monotonic() < deadline:
        got = _queue_timeout(sqs, queue_url)
        if got == expected:
            return
        time.sleep(3.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget spent waiting for VisibilityTimeout {expected} on {queue_url}")
    raise AssertionError(f"VisibilityTimeout of {queue_url} never read {expected!r} (last={got!r})")


def _wait_stack_terminal(cfn, stack_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_id)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} did not reach terminal status within {timeout_s}s (last={status})")


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack policy that Allows Update:* on one named resource leaves every other resource
    implicitly denied: an update naming only the allowed one succeeds, one touching the
    unnamed resource rolls the whole stack back with a stack-policy denial reason.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/protect-stack-resources.html
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack_name = ctx.unique_name("sim2real-stackpolicy-implicit-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_queue_template(30, 30),
        Tags=[{"Key": "sim2real", "Value": "stack-policy-implicit-deny-for-unnamed-resource"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack create failed: {status}"

    free_url = _queue_url(cfn, stack_id, "FreeQueue")
    protected_url = _queue_url(cfn, stack_id, "ProtectedQueue")

    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "LogicalResourceId/FreeQueue"},
        ]
    }
    cfn.set_stack_policy(StackName=stack_id, StackPolicyBody=json.dumps(policy))
    got_body = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert got_body == policy, f"stack policy round-trip mismatch: {got_body} != {policy}"

    # --- positive control: an update touching only the explicitly-allowed resource succeeds ---
    cfn.update_stack(StackName=stack_id, TemplateBody=_queue_template(45, 30))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update of the explicitly-allowed resource must succeed, got {status}"
    _wait_queue_timeout(ctx, sqs, free_url, "45")
    assert _queue_timeout(sqs, protected_url) == "30", "ProtectedQueue must be untouched by the first update"

    # --- break: a resource the policy never names is implicitly denied, not implicitly allowed ---
    cfn.update_stack(StackName=stack_id, TemplateBody=_queue_template(45, 60))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"an update touching a resource absent from every policy statement must be denied, got {status}"
    )

    events = [
        e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for e in page["StackEvents"]
    ]
    protected_failures = [
        e.get("ResourceStatusReason") for e in events
        if e.get("LogicalResourceId") == "ProtectedQueue" and e.get("ResourceStatus") == "UPDATE_FAILED"
    ]
    assert protected_failures == ["Action not allowed by stack policy"], (
        f"expected exactly one UPDATE_FAILED event for ProtectedQueue carrying the stack-policy "
        f"denial reason, got: {protected_failures!r}"
    )

    # --- effect absent: the denied update never reached ProtectedQueue, and the stack-wide
    # rollback left FreeQueue at its last-successful value too ---
    assert _queue_timeout(sqs, protected_url) == "30", "ProtectedQueue's VisibilityTimeout must be unchanged"
    assert _queue_timeout(sqs, free_url) == "45", "FreeQueue must have rolled back to its last successful value"

    # --- restore: naming the resource explicitly lets the identical update complete ---
    cfn.set_stack_policy(
        StackName=stack_id,
        StackPolicyBody=json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        ]}),
    )
    cfn.update_stack(StackName=stack_id, TemplateBody=_queue_template(45, 60))
    status = _wait_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"identical update must succeed once ProtectedQueue is named, got {status}"
    _wait_queue_timeout(ctx, sqs, protected_url, "60")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
