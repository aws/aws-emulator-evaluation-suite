"""deploy-sns-subscription-missing-protocol-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-subscription-missing-protocol-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_TOPIC_NOT_FOUND = ("NotFound", "Topic does not exist")
_SUB_NOT_FOUND = ("NotFound", "Subscription does not exist")
_QUEUE_NOT_FOUND = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")
_STACK_GONE = "Stack with id {} does not exist"


def _template(topic_name: str, queue_name: str, *, with_protocol: bool) -> str:
    sub: dict = {"TopicArn": {"Ref": "Topic"}, "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]}}
    if with_protocol:
        sub["Protocol"] = "sqs"
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowTopicSend",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                        }],
                    },
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "DependsOn": "QueuePolicy",
                "Properties": sub,
            },
        },
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::SNS::Subscription with no Protocol fails pre-deployment property validation and
    creates no topic, while the same template with Protocol sqs deploys, subscribes the queue and
    attaches the queue policy that lets the topic send to it.
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    # Positive control: the identical template with Protocol, through CloudFormation.
    control_topic = ctx.unique_name("sim2real-behav-cfnsub-ctrl-t-")
    control_queue = ctx.unique_name("sim2real-behav-cfnsub-ctrl-q-")
    control_stack = ctx.unique_name("sim2real-behav-cfnsub-ctrl-stack-")
    control_id = create_stack(ctx, cf, control_stack,
                              _template(control_topic, control_queue, with_protocol=True))
    status = wait_stack(cf, control_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack: expected CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cf, control_id))!r}"
    )
    partition = control_id.split(":")[1]
    control_arn = f"arn:{partition}:sns:{ctx.region}:{ctx.account}:{control_topic}"
    sub_arn = cf.describe_stack_resource(
        StackName=control_id, LogicalResourceId="Subscription"
    )["StackResourceDetail"]["PhysicalResourceId"]
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    queue_url = sqs.get_queue_url(QueueName=control_queue)["QueueUrl"]
    queue = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn", "Policy"])[
        "Attributes"]
    queue_arn = f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:{control_queue}"
    assert queue["QueueArn"] == queue_arn, f"expected QueueArn {queue_arn!r}, got {queue['QueueArn']!r}"
    # The subscription's physical id against an independent read: the topic's listed subscriptions.
    listed = [(x["SubscriptionArn"], x["Protocol"], x["Endpoint"]) for x in paginate(
        sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=control_arn)]
    assert listed == [(sub_arn, "sqs", queue_arn)], (
        f"ListSubscriptionsByTopic lists {listed!r}, expected the one subscription "
        f"{(sub_arn, 'sqs', queue_arn)!r}"
    )
    got_sub = (attrs["Protocol"], attrs["Endpoint"], attrs["TopicArn"])
    assert got_sub == ("sqs", queue_arn, control_arn), (
        f"control subscription (Protocol, Endpoint, TopicArn): expected "
        f"{('sqs', queue_arn, control_arn)!r}, got {got_sub!r}"
    )
    want_statement = [{
        "Sid": "AllowTopicSend",
        "Effect": "Allow",
        "Principal": {"Service": "sns.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
        "Condition": {"ArnEquals": {"aws:SourceArn": control_arn}},
    }]
    got_statement = json.loads(queue["Policy"])["Statement"]
    assert got_statement == want_statement, (
        f"the control queue's QueuePolicy reads back as {got_statement!r}, expected {want_statement!r}"
    )

    # The one thing broken: the same template without a Protocol.
    topic_name = ctx.unique_name("sim2real-behav-cfnsub-bad-t-")
    queue_name = ctx.unique_name("sim2real-behav-cfnsub-bad-q-")
    stack_name = ctx.unique_name("sim2real-behav-cfnsub-bad-stack-")
    stack_id = create_stack(ctx, cf, stack_name,
                            _template(topic_name, queue_name, with_protocol=False))
    status = wait_stack(cf, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reason = failed_reason(stack_events(cf, stack_id), stack_name)
    assert reason == _STACK_REASON, (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {reason!r}"
    )
    found = validation_rows(cf, stack_id)
    want = [(
        "Subscription", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Required property [Protocol] not found", "/Resources/Subscription/Properties",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = paginate(cf, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )
    topic_arn = f"arn:{partition}:sns:{ctx.region}:{ctx.account}:{topic_name}"
    expect_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), *_TOPIC_NOT_FOUND)

    for name, sid in ((stack_name, stack_id), (control_stack, control_id)):
        delete_stack(cf, sid)
        stack_gone = ("ValidationError", _STACK_GONE.format(name))
        expect_error(lambda name=name: cf.describe_stacks(StackName=name), *stack_gone)
    expect_error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn), *_SUB_NOT_FOUND)
    expect_error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"]),
                 *_QUEUE_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
