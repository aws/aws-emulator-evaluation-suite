"""cfn-deploy-neptune-event-subscription-invalid-source-type-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-event-subscription-invalid-source-type-rejected-and-rolled-back"
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

_BAD_SOURCE_TYPE = "sim2real-bogus-source-type"
_GOOD_SOURCE_TYPE = "db-cluster"
_TOPIC_GONE = ("NotFound", "Topic does not exist")


def _template(sub_name: str, source_type: str, tag_value: str) -> str:
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
                    "SourceType": source_type,
                    "Enabled": True,
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "SubscriptionName": {"Value": {"Ref": "Subscription"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Neptune::EventSubscription with an unrecognized SourceType is
    rejected by Neptune, and the stack rolls back leaving no subscription or topic; the
    identical mechanism with a documented source type still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-neptune-eventsubscription.html
    """
    nep = ctx.client("neptune")
    sns = ctx.client("sns")
    cfn = ctx.client("cloudformation")

    bad_stack = ctx.unique_name("sim2real-nep-evtbad-")
    bad_name = ctx.unique_name("sim2real-nep-evtbadname-")
    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_name, _BAD_SOURCE_TYPE, CHECK))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    events = stack_events(cfn, bad_id)
    got_reason = handler_reason(failed_reason(events, "Subscription"), ctx.account)
    want_reason = (
        "Invalid event source type. Valid types are "
        "'db-instance', 'db-security-group', 'db-parameter-group', 'db-snapshot', 'db-cluster', "
        "'db-cluster-snapshot', 'custom-engine-version', 'db-proxy', 'blue-green-deployment', "
        "'db-shard-group', 'zero-etl' (Service: Neptune, Status Code: 400, "
        "Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    assert got_reason == want_reason, (
        f"expected the Subscription CREATE_FAILED reason to equal {want_reason!r}, got "
        f"{got_reason!r}"
    )

    # The rollback deleted the topic the stack had created: SNS no longer resolves its ARN.
    topic_created = [e for e in events
                     if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Topic", "CREATE_COMPLETE")]
    assert len(topic_created) == 1, f"expected one Topic CREATE_COMPLETE event, got {len(topic_created)}"
    bad_topic_arn = topic_created[0]["PhysicalResourceId"]
    expect_error(lambda: sns.get_topic_attributes(TopicArn=bad_topic_arn), *_TOPIC_GONE)

    sub_absent = ("SubscriptionNotFound", f"Event Subscription {bad_name} not found.")
    expect_error(lambda: nep.describe_event_subscriptions(SubscriptionName=bad_name), *sub_absent)

    delete_stack(cfn, bad_id)

    # Positive control: the identical mechanism, given a documented source type, succeeds.
    good_stack = ctx.unique_name("sim2real-nep-evtgood-")
    good_name = ctx.unique_name("sim2real-nep-evtgoodname-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_name, _GOOD_SOURCE_TYPE, CHECK))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_outputs = stack_outputs(cfn, good_id)
    good_ref, topic_arn = good_outputs["SubscriptionName"], good_outputs["TopicArn"]
    assert good_ref == good_name, f"expected Ref {good_name!r}, got {good_ref!r}"

    sns_arn = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["TopicArn"]
    assert sns_arn == topic_arn, f"expected SNS to report TopicArn {topic_arn!r}, got {sns_arn!r}"

    subs = nep.describe_event_subscriptions(SubscriptionName=good_ref)["EventSubscriptionsList"]
    assert len(subs) == 1, f"DescribeEventSubscriptions({good_ref!r}) returned {len(subs)}"
    got = (subs[0]["SourceType"], subs[0]["SnsTopicArn"], subs[0]["Enabled"])
    want = (_GOOD_SOURCE_TYPE, topic_arn, True)
    assert got == want, (
        f"expected the control subscription's (SourceType, SnsTopicArn, Enabled) {want!r}, "
        f"Neptune reports {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
