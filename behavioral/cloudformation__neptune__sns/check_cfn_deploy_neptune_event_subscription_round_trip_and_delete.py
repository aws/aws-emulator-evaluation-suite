"""cfn-deploy-neptune-event-subscription-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-event-subscription-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "neptune", "sns"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_SOURCE_TYPE = "db-parameter-group"
_TOPIC_GONE = ("NotFound", "Topic does not exist")


def _template(sub_name: str, tag_value: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": t}},
            "Subscription": {
                "Type": "AWS::Neptune::EventSubscription",
                "Properties": {
                    "SubscriptionName": sub_name,
                    "SnsTopicArn": {"Ref": "Topic"},
                    "SourceType": _SOURCE_TYPE,
                    "Enabled": True,
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "SubscriptionName": {"Value": {"Ref": "Subscription"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Neptune::EventSubscription and its AWS::SNS::Topic read back through
    Neptune and SNS with the declared topic, source type, enabled flag and tags; deleting the
    stack removes both, which Neptune and SNS then refuse.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-eventsubscription.html
    """
    nep = ctx.client("neptune")
    sns = ctx.client("sns")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-nep-evt-")
    sub_name = ctx.unique_name("sim2real-nep-evtsub-")

    stack_id = create_stack(ctx, cfn, stack, _template(sub_name, CHECK))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    topic_arn, sub_ref = outputs["TopicArn"], outputs["SubscriptionName"]
    assert sub_ref == sub_name, (
        f"expected Subscription's Ref to equal its SubscriptionName {sub_name!r}, got {sub_ref!r}"
    )

    want_tags = {"sim2real": stack, "sim2real-check": CHECK}
    # The topic Ref against an independent read: ListTopics, never only a read keyed by the Ref.
    assert topic_arn in [t["TopicArn"] for t in paginate(sns, "list_topics", "Topics")], (
        f"ListTopics does not list the Topic Ref {topic_arn!r}"
    )
    sns_arn = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["TopicArn"]
    assert sns_arn == topic_arn, f"expected SNS to report TopicArn {topic_arn!r}, got {sns_arn!r}"
    topic_tags = sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]
    found = {t["Key"]: t["Value"] for t in topic_tags if not t["Key"].startswith("aws:")}
    assert found == want_tags, f"expected tags {want_tags!r} on the topic, SNS reports {topic_tags!r}"

    subs = nep.describe_event_subscriptions(SubscriptionName=sub_ref)["EventSubscriptionsList"]
    assert len(subs) == 1, f"DescribeEventSubscriptions({sub_ref!r}) returned {len(subs)}"
    sub = subs[0]
    assert sub["SnsTopicArn"] == topic_arn, (
        f"expected SnsTopicArn {topic_arn!r}, Neptune reports {sub['SnsTopicArn']!r}"
    )
    assert sub["SourceType"] == _SOURCE_TYPE, (
        f"expected SourceType {_SOURCE_TYPE!r}, Neptune reports {sub['SourceType']!r}"
    )
    assert sub["Enabled"] is True, f"expected Enabled True, Neptune reports {sub['Enabled']!r}"
    sub_tags = nep.list_tags_for_resource(ResourceName=sub["EventSubscriptionArn"])["TagList"]
    found = {t["Key"]: t["Value"] for t in sub_tags if not t["Key"].startswith("aws:")}
    assert found == want_tags, (
        f"expected tags {want_tags!r} on the subscription, Neptune reports {sub_tags!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    sub_gone = ("SubscriptionNotFound", f"Event Subscription {sub_ref} not found.")
    expect_error(lambda: nep.describe_event_subscriptions(SubscriptionName=sub_ref), *sub_gone)
    expect_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), *_TOPIC_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
