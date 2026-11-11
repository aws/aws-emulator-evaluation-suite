"""deploy-docdb-eventsubscription-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-docdb-eventsubscription-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "docdb"]

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


_SOURCE_TYPE = "db-cluster"
_EVENT_CATEGORIES = ["maintenance"]


def _template(subscription_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Subscription": {
                "Type": "AWS::DocDB::EventSubscription",
                "Properties": {
                    "SubscriptionName": subscription_name,
                    "SnsTopicArn": {"Ref": "Topic"},
                    "SourceType": _SOURCE_TYPE,
                    "EventCategories": _EVENT_CATEGORIES,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "SubscriptionId": {"Value": {"Ref": "Subscription"}},
        },
    })


def _wait_subscription_status(docdb, name: str, deadline_s: float = 300.0, poll_s: float = 3.0) -> str:
    """Poll DescribeEventSubscriptions until the subscription leaves 'creating'."""
    deadline = time.monotonic() + deadline_s
    while True:
        status = docdb.describe_event_subscriptions(SubscriptionName=name)[
            "EventSubscriptionsList"
        ][0]["Status"]
        if status != "creating":
            return status
        assert time.monotonic() < deadline, f"subscription {name!r} still {status!r} after {deadline_s}s"
        time.sleep(poll_s)


@tags("axis:happy-path", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack's AWS::DocDB::EventSubscription reads back through DocDB's own API with the
    template's SNS topic, source type, event categories and enabled flag; deleting the stack
    removes it, which DocDB then refuses by name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdb-eventsubscription.html
    """
    docdb = ctx.client("docdb")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-docdbevt-")
    subscription_name = ctx.unique_name("sim2real-docdbevt-")

    stack_id = create_stack(ctx, cfn, stack, _template(subscription_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    topic_arn = outputs["TopicArn"]
    subscription_id = outputs["SubscriptionId"]
    assert subscription_id == subscription_name, (
        f"expected Ref to equal the template's SubscriptionName {subscription_name!r}, "
        f"CloudFormation reports {subscription_id!r}"
    )

    final_status = _wait_subscription_status(docdb, subscription_name)
    assert final_status == "active", (
        f"expected the subscription to converge to 'active', DocDB reports {final_status!r}"
    )
    # Ref against an independent read: the account's subscriptions, every page.
    subs = [x for x in paginate(docdb, "describe_event_subscriptions", "EventSubscriptionsList")
            if x["CustSubscriptionId"] == subscription_name]
    assert len(subs) == 1, f"DescribeEventSubscriptions lists {subs!r}"
    sub = subs[0]
    assert sub["CustSubscriptionId"] == subscription_name, (
        f"expected the subscription's own id to equal Ref {subscription_name!r}, DocDB "
        f"reports {sub['CustSubscriptionId']!r}"
    )
    assert sub["SnsTopicArn"] == topic_arn, (
        f"expected SnsTopicArn {topic_arn!r}, DocDB reports {sub['SnsTopicArn']!r}"
    )
    assert sub["SourceType"] == _SOURCE_TYPE, (
        f"expected SourceType {_SOURCE_TYPE!r}, DocDB reports {sub['SourceType']!r}"
    )
    assert sub["Enabled"] is True, f"expected Enabled True, DocDB reports {sub['Enabled']!r}"
    assert set(sub["EventCategoriesList"]) == set(_EVENT_CATEGORIES), (
        f"expected EventCategories {_EVENT_CATEGORIES!r}, DocDB reports "
        f"{sub['EventCategoriesList']!r}"
    )

    delete_stack(cfn, stack_id)
    event_subscriptions_gone = (
        "SubscriptionNotFound",
        f"Event Subscription {subscription_name} not found.",
    )
    expect_error(lambda: docdb.describe_event_subscriptions(SubscriptionName=subscription_name),
                 *event_subscriptions_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
