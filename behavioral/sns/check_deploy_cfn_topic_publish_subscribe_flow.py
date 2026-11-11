"""deploy-cfn-topic-publish-subscribe-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-topic-publish-subscribe-flow"
GROUP = "state-machine"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed SNS Topic + SQS Subscription actually delivers a
    published message to the subscriber, not just reaches CREATE_COMPLETE."""
    resource_tags = [
        {"Key": "sim2real", "Value": "sns-cfn-pubsub"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]
    template = {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"Tags": resource_tags}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": resource_tags}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}
                                },
                            }
                        ],
                    },
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    }

    outputs = _deploy_cfn(ctx, json.dumps(template))
    topic_arn = outputs["TopicArn"]
    queue_url = outputs["QueueUrl"]

    sns = ctx.client("sns")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, (
        f"GetTopicAttributes returned TopicArn {attrs['TopicArn']!r}, expected {topic_arn!r}"
    )

    body_token = ctx.unique_name("sim2real-cfn-pubsub-")
    message_id = sns.publish(TopicArn=topic_arn, Message=body_token)["MessageId"]
    assert message_id, "Publish must return a MessageId"

    envelope = _poll_for_envelope(ctx, queue_url, body_token, timeout_s=60.0)
    assert envelope["Message"] == body_token, (
        f"delivered envelope Message {envelope['Message']!r} != published {body_token!r}"
    )
    assert envelope["TopicArn"] == topic_arn, (
        f"delivered envelope TopicArn {envelope['TopicArn']!r} != {topic_arn!r}"
    )
    assert envelope["MessageId"] == message_id, (
        f"delivered envelope MessageId {envelope['MessageId']!r} != Publish MessageId {message_id!r}"
    )
    assert envelope["Type"] == "Notification", (
        f"unexpected envelope Type {envelope.get('Type')!r}, expected 'Notification'"
    )


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-sns-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_for_envelope(ctx, queue_url: str, body_token: str, timeout_s: float = 60.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if envelope.get("Message") == body_token:
                return envelope
    raise AssertionError(f"message {body_token!r} never arrived on the subscribed queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
