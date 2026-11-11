"""change-set-notification-arns-deliver-every-stack-event-to-the-topic."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-notification-arns-deliver-every-stack-event-to-the-topic"
GROUP = "change_sets"
SERVICES = ["cloudformation", "sns", "sqs", "sts"]

def _teardown(undo, *not_found):
    """A cleanup running undo() where a failed delete raises unless it is a not-found code."""
    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in not_found:
                raise
    return run_undo

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_KEYS_HEAD = ["StackId", "Timestamp", "EventId", "LogicalResourceId", "Namespace"]
_KEYS_TAIL = ["ResourceProperties", "ResourceStatus", "ResourceStatusReason", "DetailedStatus",
              "ResourceType", "StackName", "ClientRequestToken"]
_LINE = re.compile(r"^(\w+)='(.*)'$", re.M)


def _template(*handles, output=False):
    body = {"Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"} for h in handles}}
    if output:
        body["Outputs"] = {"Topics": {"Value": {"Fn::Join": [",", {"Ref": "AWS::NotificationARNs"}]}}}
    return json.dumps(body)


def _wire_topic_to_queue(ctx, sns, sqs, label):
    """A topic delivering (non-raw) into a queue that only that topic may write; returns both."""
    topic = sns.create_topic(Name=ctx.unique_name(f"sim2real-xsvc-{label}-t-"), Tags=_TAGS)["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=topic), "NotFound"))
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-xsvc-{label}-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                       "Action": "sqs:SendMessage", "Resource": arn,
                       "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub), "NotFound"))
    return topic, url


def _drain(sqs, url):
    """Receive and delete what the queue holds now; return (envelope, fields) per message."""
    out = []
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                               WaitTimeSeconds=2).get("Messages", [])
    for m in msgs:
        env = json.loads(m["Body"])
        out.append((env, _LINE.findall(env["Message"])))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _collect(sqs, url, want_ids, *, timeout_s=120.0):
    """Drain until every EventId in want_ids has arrived; return {EventId: (envelope, fields)}."""
    got = {}
    deadline = time.monotonic() + timeout_s
    while not want_ids <= set(got):
        for env, fields in _drain(sqs, url):
            got[dict(fields)["EventId"]] = (env, fields)
        if time.monotonic() > deadline:
            raise AssertionError(f"events never delivered: {sorted(want_ids - set(got))!r}")
    return got


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _expected_keys(event):
    """The notification's field order for one event: PhysicalResourceId appears once assigned,
    PrincipalId only on the stack resource's own events."""
    keys = list(_KEYS_HEAD)
    if event.get("PhysicalResourceId"):
        keys.append("PhysicalResourceId")
    if event["ResourceType"] == "AWS::CloudFormation::Stack":
        keys.append("PrincipalId")
    keys += _KEYS_TAIL
    return keys

@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """NotificationARNs on CreateChangeSet deliver every StackEvent of the execution to the topic in
    the Key='value' line format, are echoed by DescribeStacks, and resolve AWS::NotificationARNs.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    topic, url = _wire_topic_to_queue(ctx, sns, sqs, "csnotif")

    stack_name = ctx.unique_name("sim2real-xsvc-csnotif-")
    created = cf.create_change_set(StackName=stack_name, ChangeSetType="CREATE", Tags=_TAGS,
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csnotif-cs-"),
                                   TemplateBody=_template("Handle", output=True),
                                   NotificationARNs=[topic])
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert cs.get("NotificationARNs") == [topic], cs.get("NotificationARNs")
    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"execute: {stack['StackStatus']!r}"
    assert stack.get("NotificationARNs") == [topic], stack.get("NotificationARNs")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    assert outputs == {"Topics": topic}, f"AWS::NotificationARNs must resolve to {topic}: {outputs!r}"

    caller_id = sts.get_caller_identity()["UserId"]
    events = {e["EventId"]: e for e in _events(cf, stack_id)}
    delivered = _collect(sqs, url, set(events), timeout_s=_cap(ctx, 120.0))
    assert set(delivered) == set(events), sorted(set(delivered) ^ set(events))
    for event_id, (env, fields) in delivered.items():
        event = events[event_id]
        assert (env["Type"], env["TopicArn"], env["Subject"]) == (
            "Notification", topic, "AWS CloudFormation Notification"), env
        assert [k for k, _ in fields] == _expected_keys(event), f"message keys: {[k for k, _ in fields]!r}"
        f = dict(fields)
        assert (f["StackId"], f["StackName"], f["Namespace"]) == (stack_id, stack_name, ctx.account), f
        assert (f["LogicalResourceId"], f["ResourceStatus"], f["ResourceType"]) == (
            event["LogicalResourceId"], event["ResourceStatus"], event["ResourceType"]), (f, event)
        assert f["ResourceStatusReason"] == (event.get("ResourceStatusReason") or ""), (f, event)
        assert f["DetailedStatus"] == (event.get("DetailedStatus") or ""), (f, event)
        if event.get("PhysicalResourceId"):
            assert f["PhysicalResourceId"] == event["PhysicalResourceId"], (f, event)
        if event["ResourceType"] == "AWS::CloudFormation::Stack":
            assert f["PrincipalId"] == caller_id, f"notification PrincipalId: {f['PrincipalId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
