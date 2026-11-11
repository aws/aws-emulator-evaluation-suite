"""deploy-cfn-subscription-raw-message-delivery-toggled-in-place-changes-delivered-envelope."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-subscription-raw-message-delivery-toggled-in-place-changes-delivered-envelope"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

#: A stack create/update here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


@tags(
    "axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A stack's AWS::SNS::Subscription RawMessageDelivery, toggled false->true by a stack
    update that keeps the same subscription, changes a published message's delivered body from
    a JSON notification envelope to the bare message.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-behav-cfnraw-")
    stack_id = _create(ctx, cfn, stack_name, _template("false"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", (
        f"create ended {_stack(cfn, stack_id)!r}"
    )

    outputs = _outputs(cfn, stack_id)
    topic_arn, queue_url = outputs["TopicArn"], outputs["QueueUrl"]
    sub_arn_before = _physical_id(cfn, stack_id, "Subscription")

    attrs_before = sns.get_subscription_attributes(SubscriptionArn=sub_arn_before)["Attributes"]
    assert attrs_before["RawMessageDelivery"] == "false", attrs_before

    marker_wrapped = ctx.unique_name("sim2real-behav-cfnraw-wrapped-")
    sns.publish(TopicArn=topic_arn, Message=marker_wrapped)
    wrapped_body = _receive_body(ctx, sqs, queue_url, timeout_s=_cap(ctx, 180.0))
    wrapped = json.loads(wrapped_body)
    assert wrapped["Type"] == "Notification", (
        f"RawMessageDelivery=false must deliver a JSON notification envelope, got {wrapped!r}"
    )
    assert wrapped["Message"] == marker_wrapped, (
        f"the envelope's Message must carry the published body, got {wrapped!r}"
    )

    cfn.update_stack(StackName=stack_id, TemplateBody=_template("true"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", (
        f"update ended {_stack(cfn, stack_id)!r}"
    )

    sub_arn_after = _physical_id(cfn, stack_id, "Subscription")
    assert sub_arn_after == sub_arn_before, (
        f"RawMessageDelivery is updatable in place; the subscription SNS minted must be unchanged: "
        f"{sub_arn_before!r} before, {sub_arn_after!r} after"
    )

    attrs_after = sns.get_subscription_attributes(SubscriptionArn=sub_arn_after)["Attributes"]
    assert attrs_after["RawMessageDelivery"] == "true", attrs_after

    marker_raw = ctx.unique_name("sim2real-behav-cfnraw-raw-")
    sns.publish(TopicArn=topic_arn, Message=marker_raw)
    raw_body = _receive_body(ctx, sqs, queue_url, timeout_s=_cap(ctx, 180.0))
    assert raw_body == marker_raw, (
        f"RawMessageDelivery=true must deliver the published body verbatim, got {raw_body!r}"
    )


def _template(raw_message_delivery: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Queue": {"Type": "AWS::SQS::Queue"},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowThisTopic",
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
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                    "RawMessageDelivery": raw_message_delivery,
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    })


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settled",
    )


def _receive_body(ctx, sqs, queue_url: str, *, timeout_s: float) -> str:
    """Long-poll one message off ``queue_url``, delete it, and return its body."""
    msgs = _poll(
        lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, what=f"a message on {queue_url}",
    )
    body = msgs[0]["Body"]
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return body


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body,
        Tags=[{"Key": "sim2real", "Value": CHECK}], **kw,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
