"""deploy-sns-topic-inline-policy-lifecycle-then-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-topic-inline-policy-lifecycle-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

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

_NOT_FOUND = ("NotFound", "Topic does not exist")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SNS::TopicInlinePolicy's Ref is the topic's own arn and its
    PolicyDocument reads back as the topic's Policy attribute, and the stack delete removes the
    topic (NotFound)."""
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-behav-topicinl-")
    stack_name = ctx.unique_name("sim2real-behav-topicinl-stack-")
    statement = {
        "Sid": "sim2real-allow-account-publish",
        "Effect": "Allow",
        "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
        "Action": "SNS:Publish",
        "Resource": {"Ref": "Topic"},
    }
    resources = {
        "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
        "InlinePolicy": {
            "Type": "AWS::SNS::TopicInlinePolicy",
            "Properties": {
                "TopicArn": {"Ref": "Topic"},
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]},
            },
        },
    }
    outputs_block = {
        "TopicArn": {"Value": {"Ref": "Topic"}},
        "InlinePolicyRef": {"Value": {"Ref": "InlinePolicy"}},
    }
    template = json.dumps({"Resources": resources, "Outputs": outputs_block})

    stack_id = create_stack(ctx, cf, stack_name, template)
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    topic_arn = outputs["TopicArn"]
    partition = stack_id.split(":")[1]
    want_arn = f"arn:{partition}:sns:{ctx.region}:{ctx.account}:{topic_name}"
    assert topic_arn == want_arn, f"Ref Topic was {topic_arn!r}, expected the documented ARN {want_arn!r}"

    # The type's primary identifier is the topic's own arn (AWS::SNS::TopicInlinePolicy has no
    # identity of its own), so Ref must equal both the topic arn and the stack's physical id.
    physical_id = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="InlinePolicy"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert outputs["InlinePolicyRef"] == topic_arn, (
        f"Ref InlinePolicy was {outputs['InlinePolicyRef']!r}, expected the topic arn {topic_arn!r}"
    )
    assert physical_id == topic_arn, (
        f"InlinePolicy's PhysicalResourceId was {physical_id!r}, expected the topic arn {topic_arn!r}"
    )

    attributes = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attributes["TopicArn"] == want_arn, (
        f"SNS reports TopicArn {attributes['TopicArn']!r}, expected {want_arn!r}"
    )
    policy = json.loads(attributes["Policy"])
    want_statement = [{
        "Sid": "sim2real-allow-account-publish", "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
        "Action": "SNS:Publish", "Resource": topic_arn,
    }]
    assert policy["Statement"] == want_statement, (
        f"the topic policy reads back the statements {policy['Statement']!r}, expected "
        f"{want_statement!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
