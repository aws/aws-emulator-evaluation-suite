"""change-set-empty-notification-arns-stops-delivery-until-restored."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-empty-notification-arns-stops-delivery-until-restored"
GROUP = "change_sets"
SERVICES = ["cloudformation", "sns", "sqs"]

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
_LINE = re.compile(r"^(\w+)='(.*)'$", re.M)


def _template(*handles):
    return json.dumps({"Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"}
                                     for h in handles}})


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


def _create(ctx, cf, label, topic):
    created = cf.create_change_set(StackName=ctx.unique_name(f"sim2real-xsvc-csnoff-{label}-"),
                                   ChangeSetType="CREATE", Tags=_TAGS,
                                   ChangeSetName=ctx.unique_name("sim2real-xsvc-csnoff-cs-"),
                                   TemplateBody=_template("One"), NotificationARNs=[topic])
    ctx.on_cleanup(lambda: _delete_stack(cf, created["StackId"]))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", (
        f"create change set {label}: {cs['Status']!r} {cs.get('StatusReason')!r}, expected CREATE_COMPLETE")
    cf.execute_change_set(ChangeSetName=created["Id"])
    return created["StackId"]


def _update(ctx, cf, stack_id, handles, **notify):
    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 TemplateBody=_template(*handles),
                                 ChangeSetName=ctx.unique_name("sim2real-xsvc-csnoff-cs-"),
                                 **notify)["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"update change set: {cs.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=cs_id)


@tags("axis:negative-delivery", "cap:c3", "concern:deploy", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """An UPDATE change set with NotificationARNs=[] clears a stack's topic; the update AFTER it
    is silent while a twin that never cleared keeps delivering, and restoring the topic resumes
    delivery on the update after that.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic, url = _wire_topic_to_queue(ctx, sns, sqs, "csnoff")

    cleared, twin = _create(ctx, cf, "a", topic), _create(ctx, cf, "b", topic)
    for sid in (cleared, twin):
        status = _wait_stack(cf, sid, timeout_s=_cap(ctx, 300.0))["StackStatus"]
        assert status == "CREATE_COMPLETE", f"stack {sid} ended {status!r}, expected CREATE_COMPLETE"
    # The create's own deliveries are drained first so later reads see only the updates.
    seen = set(_collect(sqs, url, {e["EventId"] for sid in (cleared, twin) for e in _events(cf, sid)
                                   if e["ResourceStatus"] != "REVIEW_IN_PROGRESS"},
                            timeout_s=_cap(ctx, 120.0)))

    # Clear: NotificationARNs=[] takes effect before the clearing update's OWN terminal stack
    # event fires, so that one UPDATE_COMPLETE is swallowed; every earlier event of the same
    # update still publishes to the topic attached when the update started. The quiet period
    # proper is graded on the update after this one.
    cleared_before = {e["EventId"] for e in _events(cf, cleared)}
    twin_before = {e["EventId"] for e in _events(cf, twin)}
    _update(ctx, cf, cleared, ("One", "Two"), NotificationARNs=[])
    _update(ctx, cf, twin, ("One", "Two"))
    for sid in (cleared, twin):
        status = _wait_stack(cf, sid, timeout_s=_cap(ctx, 300.0))["StackStatus"]
        assert status == "UPDATE_COMPLETE", f"stack {sid} ended {status!r}, expected UPDATE_COMPLETE"
    arns = cf.describe_stacks(StackName=cleared)["Stacks"][0].get("NotificationARNs", [])
    assert arns == [], f"NotificationARNs=[] must clear the stack's topics, DescribeStacks shows {arns!r}"
    assert cf.describe_stacks(StackName=twin)["Stacks"][0].get("NotificationARNs") == [topic], (
        "omitting NotificationARNs must keep the stack's topic")
    clear_events = [e for e in _events(cf, cleared) if e["EventId"] not in cleared_before]
    twin_new = {e["EventId"] for e in _events(cf, twin)} - twin_before
    swallowed = [e for e in clear_events if e["ResourceType"] == "AWS::CloudFormation::Stack"
                 and e["ResourceStatus"] == "UPDATE_COMPLETE"]
    assert len(swallowed) == 1, (
        f"clearing update: expected exactly one stack UPDATE_COMPLETE event, got {swallowed!r}")
    clear_new = {e["EventId"] for e in clear_events} - {swallowed[0]["EventId"]}
    got = _collect(sqs, url, clear_new | twin_new, timeout_s=_cap(ctx, 120.0))
    got.update({dict(f)["EventId"]: (env, f) for env, f in _drain(sqs, url)})
    seen |= set(got)
    assert swallowed[0]["EventId"] not in got, (
        f"the clearing update's own terminal UPDATE_COMPLETE must not reach the topic it just "
        f"cleared, yet it was delivered: {swallowed[0]['EventId']!r}")

    # Quiet leg: the NEXT update, starting with the association already cleared, must publish
    # nothing while the twin -- updated at the same instant -- keeps delivering every event.
    before_quiet = {e["EventId"] for e in _events(cf, cleared)}
    twin_before2 = {e["EventId"] for e in _events(cf, twin)}
    _update(ctx, cf, cleared, ("One", "Two", "Three"))
    _update(ctx, cf, twin, ("One", "Two", "Three"))
    for sid in (cleared, twin):
        status = _wait_stack(cf, sid, timeout_s=_cap(ctx, 300.0))["StackStatus"]
        assert status == "UPDATE_COMPLETE", f"stack {sid} ended {status!r}, expected UPDATE_COMPLETE"
    assert cf.describe_stacks(StackName=cleared)["Stacks"][0].get("NotificationARNs", []) == [], (
        "omitting NotificationARNs after clearing must keep the stack silent")
    quiet_new = {e["EventId"] for e in _events(cf, cleared)} - before_quiet
    twin_new2 = {e["EventId"] for e in _events(cf, twin)} - twin_before2
    got = _collect(sqs, url, twin_new2, timeout_s=_cap(ctx, 120.0))
    got.update({dict(f)["EventId"]: (env, f) for env, f in _drain(sqs, url)})
    leaked = sorted(quiet_new & set(got))
    assert leaked == [], f"events of the stack with no topics were delivered: {leaked!r}"
    stray = sorted((eid, dict(f)["StackId"]) for eid, (_, f) in got.items()
                   if eid not in twin_new2 and eid not in seen)
    assert stray == [], f"only the twin's quiet-leg events may arrive, also delivered: {stray!r}"

    # Restore: re-add the topic (this update's own events use the pre-op empty list, so they are
    # drained, not asserted), then the update AFTER that delivers on the restored topic.
    _update(ctx, cf, cleared, ("One", "Two", "Three", "Four"), NotificationARNs=[topic])
    status = _wait_stack(cf, cleared, timeout_s=_cap(ctx, 300.0))["StackStatus"]
    assert status == "UPDATE_COMPLETE", f"restore update ended {status!r}, expected UPDATE_COMPLETE"
    assert cf.describe_stacks(StackName=cleared)["Stacks"][0].get("NotificationARNs") == [topic], (
        "re-adding NotificationARNs must take effect immediately")
    _drain(sqs, url)

    before_restore = {e["EventId"] for e in _events(cf, cleared)}
    _update(ctx, cf, cleared, ("One", "Two", "Three", "Four", "Five"))
    status = _wait_stack(cf, cleared, timeout_s=_cap(ctx, 300.0))["StackStatus"]
    assert status == "UPDATE_COMPLETE", f"update after restore ended {status!r}, expected UPDATE_COMPLETE"
    assert cf.describe_stacks(StackName=cleared)["Stacks"][0].get("NotificationARNs") == [topic], (
        "omitting NotificationARNs after restoring must keep the stack's topic")
    restored = {e["EventId"] for e in _events(cf, cleared)} - before_restore
    delivered = _collect(sqs, url, restored, timeout_s=_cap(ctx, 120.0))
    assert {dict(f)["StackId"] for _, f in delivered.values()} == {cleared}, delivered


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
