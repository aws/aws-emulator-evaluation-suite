"""cfn-sqs-queueinlinepolicy-ref-is-queue-url-and-removed-by-stack-update."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queueinlinepolicy-ref-is-queue-url-and-removed-by-stack-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")


def _template(queue_name: str, with_inline_policy: bool) -> str:
    resources: dict[str, Any] = {
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
    }
    if with_inline_policy:
        resources["QueueInlinePolicy"] = {
            "Type": "AWS::SQS::QueueInlinePolicy",
            "Properties": {
                "Queue": {"Ref": "Queue"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowAccountRoot",
                        "Effect": "Allow",
                        "Principal": {"AWS": {"Ref": "AWS::AccountId"}},
                        "Action": "sqs:ReceiveMessage",
                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                    }],
                },
            },
        }
    outputs = {"QueueUrl": {"Value": {"Ref": "Queue"}}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _identity(sqs, queue_url: str) -> tuple[str, str]:
    """``(QueueArn, CreatedTimestamp)``; a queue recreated under the same URL has a new one."""
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "CreatedTimestamp"]
    )["Attributes"]
    return attrs["QueueArn"], attrs["CreatedTimestamp"]


def _poll_policy_gone(sqs, queue_url: str, *, timeout_s: float = 60.0,
                      interval_s: float = 2.0) -> dict[str, str]:
    """Poll the queue's attributes until no Policy is reported; SQS attribute reads converge."""
    deadline = time.monotonic() + timeout_s
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"]
        ).get("Attributes", {})
        if "Policy" not in attrs or time.monotonic() >= deadline:
            return attrs
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SQS::QueueInlinePolicy's Ref is the queue's own URL, not a generated
    id; the queue's Policy attribute carries the declared statement, and a stack update that
    drops the resource removes the queue's policy, proven through SQS, not CFN."""
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-cfn-qip-")
    stack_name = ctx.unique_name("sim2real-behav-cfn-qip-")

    stack_id = create_stack(ctx, cf, stack_name, _template(queue_name, with_inline_policy=True))
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    queue_url = stack_outputs(cf, stack_id)["QueueUrl"]
    # The queue's Ref against an independent read: GetQueueUrl by the declared name.
    listed_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert queue_url == listed_url, f"Ref Queue {queue_url!r} != GetQueueUrl {listed_url!r}"
    inline_policy_ref = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="QueueInlinePolicy"
    )["StackResourceDetail"]["PhysicalResourceId"]

    # QueueInlinePolicy's Ref is documented to be the queue URL, unlike QueuePolicy's generated id.
    assert inline_policy_ref == queue_url, (
        f"QueueInlinePolicy's PhysicalResourceId (Ref) {inline_policy_ref!r} must be the queue "
        f"URL {queue_url!r}"
    )

    # Read through SQS, the owning service: the queue carries the policy the stack declared.
    policy_json = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["Policy"]
    )["Attributes"]["Policy"]
    statements = json.loads(policy_json)["Statement"]
    identity_before = _identity(sqs, queue_url)
    partition = stack_id.split(":")[1]
    want_statements = [{
        "Sid": "AllowAccountRoot", "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
        "Action": "sqs:ReceiveMessage", "Resource": identity_before[0],
    }]
    assert statements == want_statements, (
        f"the queue policy reads back the statements {statements!r}, expected {want_statements!r}"
    )

    # ---- update: drop the QueueInlinePolicy resource, keeping the queue ----
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(queue_name, with_inline_policy=False)
    )
    updated = wait_stack(cf, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {updated!r}"

    resources = {
        r["LogicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert "QueueInlinePolicy" not in resources, (
        f"QueueInlinePolicy logical resource still present after the update: {resources!r}"
    )

    # The removal is real at SQS, not merely reported by CFN: the queue has no Policy attribute.
    attrs_after = _poll_policy_gone(sqs, queue_url)
    assert "Policy" not in attrs_after, (
        f"queue {queue_url!r} still carries a Policy attribute after the QueueInlinePolicy "
        f"resource was removed by the stack update: {attrs_after!r}"
    )

    # The queue itself is untouched by the update: the same queue, not a recreated one.
    identity_after = _identity(sqs, queue_url)
    assert identity_after == identity_before, (
        f"queue (QueueArn, CreatedTimestamp) changed across the update: "
        f"{identity_before!r} -> {identity_after!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"]),
                 *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
