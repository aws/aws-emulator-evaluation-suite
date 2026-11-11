"""deploy-rds-event-subscription-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-event-subscription-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds", "sns"]

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

_TOPIC_NOT_FOUND = ("NotFound", "Topic does not exist")



def _template(sub_name: str, topic_name: str, categories: list[str]) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": topic_name},
            },
            "EventSub": {
                "Type": "AWS::RDS::EventSubscription",
                "Properties": {
                    "SubscriptionName": sub_name,
                    "SnsTopicArn": {"Ref": "Topic"},
                    "SourceType": "db-parameter-group",
                    "EventCategories": categories,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SubscriptionNameOut": {"Value": {"Ref": "EventSub"}},
            "TopicArnOut": {"Value": {"Ref": "Topic"}},
        },
    })


def _topic_arns_named(sns, topic_name: str) -> list[str]:
    """Every listed topic ARN whose name is ``topic_name``."""
    return [t["TopicArn"] for t in paginate(sns, "list_topics", "Topics")
            if t["TopicArn"].rsplit(":", 1)[-1] == topic_name]


def _subscriptions_named(rds, sub_name: str) -> list[dict]:
    return [s for s in paginate(rds, "describe_event_subscriptions", "EventSubscriptionsList")
            if s["CustSubscriptionId"] == sub_name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An RDS event subscription over an SNS topic deployed by CloudFormation reads back through
    RDS and SNS with the Ref values, and both are gone through their own not-found faults once the
    stack is deleted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    sub_name = ctx.unique_name("sim2real-cfnrds-sub-")
    topic_name = ctx.unique_name("sim2real-cfnrds-topic-")
    stack_name = ctx.unique_name("sim2real-cfnrds-stk-")

    stack_id = create_stack(ctx, cf, stack_name,
                            _template(sub_name, topic_name, ["configuration change"]))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack settled at {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    assert outputs["SubscriptionNameOut"] == sub_name, (
        f"the EventSubscription Ref was {outputs['SubscriptionNameOut']!r}, expected {sub_name!r}"
    )

    subs = _subscriptions_named(rds, sub_name)
    assert len(subs) == 1, f"DescribeEventSubscriptions listed {len(subs)} subscriptions named it"
    sub = subs[0]
    assert sub["CustSubscriptionId"] == outputs["SubscriptionNameOut"], (
        f"RDS subscription id {sub['CustSubscriptionId']!r} differs from the stack Ref"
    )
    assert sub["SnsTopicArn"] == outputs["TopicArnOut"], (
        f"RDS SnsTopicArn {sub['SnsTopicArn']!r} != stack Ref output {outputs['TopicArnOut']!r}"
    )
    assert sub["SourceType"] == "db-parameter-group", f"source type was {sub['SourceType']!r}"
    assert sorted(sub["EventCategoriesList"]) == ["configuration change"], (
        f"event categories were {sub['EventCategoriesList']!r}"
    )
    assert sub["Enabled"] is True, f"subscription enabled flag was {sub['Enabled']!r}"
    assert sub["Status"] == "active", f"subscription status was {sub['Status']!r}"

    topic_arn = outputs["TopicArnOut"]
    assert _topic_arns_named(sns, topic_name) == [topic_arn], (
        f"ListTopics named {topic_name!r}: {_topic_arns_named(sns, topic_name)!r}, "
        f"expected only the Topic Ref"
    )
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, f"GetTopicAttributes TopicArn was {attrs['TopicArn']!r}"
    topic_tags = {t["Key"]: t["Value"]
                  for t in sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]
                  if not t["Key"].startswith("aws:")}
    assert topic_tags == {"sim2real": stack_name}, f"topic tags {topic_tags!r}"

    delete_stack(cf, stack_id)

    sub_not_found = ("SubscriptionNotFound", f"Event Subscription {sub_name} not found.")
    expect_error(lambda: rds.describe_event_subscriptions(SubscriptionName=sub_name), *sub_not_found)
    expect_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), *_TOPIC_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
