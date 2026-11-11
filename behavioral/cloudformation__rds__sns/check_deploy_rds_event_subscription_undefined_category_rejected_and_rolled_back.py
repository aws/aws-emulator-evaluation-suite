"""deploy-rds-event-subscription-undefined-category-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-event-subscription-undefined-category-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_REJECTED = (
    "Category : backup not found for source type db-parameter-group. "
    "(Service: Rds, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InternalFailure",
)


def _sub_not_found(sub_name):
    return ("SubscriptionNotFound", f"Event Subscription {sub_name} not found.")


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


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An RDS event subscription naming a category RDS does not define for its source type fails
    with RDS's exact message and the rollback removes subscription and topic; the same template
    with a defined category deploys and reads back through RDS and SNS.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Events.Messages.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    bad_sub = ctx.unique_name("sim2real-cfnrds-badsub-")
    bad_topic = ctx.unique_name("sim2real-cfnrds-badtopic-")
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrds-badstk-"),
                          _template(bad_sub, bad_topic, ["backup"]))
    bad_status = wait_stack(cf, bad_id, timeout_s=600.0)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"invalid category stack settled at {bad_status!r}, expected ROLLBACK_COMPLETE"
    )
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "EventSub"),
                         ctx.account, bad_sub, bad_topic)
    assert got == _REJECTED, f"the EventSub CREATE_FAILED reason was {got!r}, expected {_REJECTED!r}"
    # The rollback itself removed both, before this check deletes the stack.
    bad_not_found = _sub_not_found(bad_sub)
    expect_error(lambda: rds.describe_event_subscriptions(SubscriptionName=bad_sub), *bad_not_found)
    assert _topic_arns_named(sns, bad_topic) == [], (
        f"the rolled-back topic is still listed: {_topic_arns_named(sns, bad_topic)!r}"
    )
    delete_stack(cf, bad_id)

    # ---- Positive control: the same template with a category RDS defines. ----
    good_sub = ctx.unique_name("sim2real-cfnrds-goodsub-")
    good_topic = ctx.unique_name("sim2real-cfnrds-goodtopic-")
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrds-goodstk-"),
                           _template(good_sub, good_topic, ["configuration change"]))
    good_status = wait_stack(cf, good_id, timeout_s=600.0)
    assert good_status == "CREATE_COMPLETE", (
        f"control stack settled at {good_status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    outputs = stack_outputs(cf, good_id)
    subs = rds.describe_event_subscriptions(SubscriptionName=good_sub)["EventSubscriptionsList"]
    assert len(subs) == 1, f"DescribeEventSubscriptions by name returned {len(subs)} subscriptions"
    sub = subs[0]
    assert (sub["CustSubscriptionId"], sub["SnsTopicArn"], sub["SourceType"],
            sorted(sub["EventCategoriesList"]), sub["Enabled"]) == (
        outputs["SubscriptionNameOut"], outputs["TopicArnOut"], "db-parameter-group",
        ["configuration change"], True,
    ), f"the control subscription read back as {sub!r}"
    assert outputs["SubscriptionNameOut"] == good_sub, (
        f"the control Ref was {outputs['SubscriptionNameOut']!r}, expected {good_sub!r}"
    )
    assert _topic_arns_named(sns, good_topic) == [outputs["TopicArnOut"]], (
        f"ListTopics named {good_topic!r} did not return exactly the control Topic Ref"
    )

    delete_stack(cf, good_id)
    good_not_found = _sub_not_found(good_sub)
    expect_error(lambda: rds.describe_event_subscriptions(SubscriptionName=good_sub), *good_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
