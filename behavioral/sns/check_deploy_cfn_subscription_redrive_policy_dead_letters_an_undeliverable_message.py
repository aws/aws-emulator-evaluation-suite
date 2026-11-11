"""deploy-cfn-subscription-redrive-policy-dead-letters-an-undeliverable-message."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-subscription-redrive-policy-dead-letters-an-undeliverable-message"
GROUP = "deploy"
SERVICES = ["sns"]


def _template() -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]

    def _allow_sns(queue: str) -> dict:
        return {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": queue}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": [queue, "Arn"]},
                    "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}}}]},
            },
        }

    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": tags_}},
            # The endpoint deliberately has no queue policy: SNS may not send to it.
            "Endpoint": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "DeadLetter": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "DeadLetterPolicy": _allow_sns("DeadLetter"),
            "Control": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": tags_}},
            "ControlPolicy": _allow_sns("Control"),
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Endpoint", "Arn"]},
                    "RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["DeadLetter", "Arn"]}},
                },
            },
            "ControlSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Control", "Arn"]}},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "SubscriptionArn": {"Value": {"Ref": "Subscription"}},
            "EndpointUrl": {"Value": {"Ref": "Endpoint"}},
            "DeadLetterUrl": {"Value": {"Ref": "DeadLetter"}},
            "DeadLetterArn": {"Value": {"Fn::GetAtt": ["DeadLetter", "Arn"]}},
            "ControlUrl": {"Value": {"Ref": "Control"}},
        },
    })


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation RedrivePolicy sends a message the endpoint queue's policy refuses to the
    dead-letter queue as the original notification, while a control subscription receives it.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    out = _create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sns-cfndlq-"), _template())
    topic = out["TopicArn"]

    attrs = sns.get_subscription_attributes(SubscriptionArn=out["SubscriptionArn"])["Attributes"]
    redrive = json.loads(attrs.get("RedrivePolicy", "{}"))
    assert redrive == {"deadLetterTargetArn": out["DeadLetterArn"]}, (
        f"the deployed subscription's RedrivePolicy reads back as {redrive!r}")

    body = ctx.unique_name("sim2real-undeliverable-")
    mid = sns.publish(TopicArn=topic, Message=body)["MessageId"]
    assert mid, "Publish must return a MessageId even though one subscriber cannot receive it"

    control = _drain(sqs, out["ControlUrl"], body, 60)
    assert [e["Message"] for e in control] == [body], (
        f"the control subscription must receive the message exactly as published; got {control!r}")
    dead = _drain(sqs, out["DeadLetterUrl"], body, 120)
    assert len(dead) == 1, f"the dead-letter queue must hold the one undeliverable message, got {dead!r}"
    letter = dead[0]
    assert (letter.get("Type"), letter.get("Message"), letter.get("TopicArn"), letter.get("MessageId")) == (
        "Notification", body, topic, mid), (
        "the dead-lettered message must be the original notification (Type, Message, TopicArn, "
        f"MessageId); got {letter!r}")
    # The control's arrival is the barrier for the endpoint's absence.
    endpoint = _drain(sqs, out["EndpointUrl"], None, 6)
    assert endpoint == [], (
        f"the endpoint whose policy does not admit SNS received {len(endpoint)} message(s)")


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    def _cleanup():
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    cfn.create_stack(StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _drain(sqs, url: str, body: str | None, timeout_s: float) -> list[dict]:
    """Receive and delete until a notification carrying ``body`` arrives (or, with ``body``
    None, until the deadline); returns every parsed envelope drained."""
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if body is not None and any(e.get("Message") == body for e in out):
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
