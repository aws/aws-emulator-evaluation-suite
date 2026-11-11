"""deploy-cfn-fifo-topic-delivers-in-order-and-deduplicates-by-content."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-fifo-topic-delivers-in-order-and-deduplicates-by-content"
GROUP = "deploy"
SERVICES = ["sns"]

_BODIES = ["one", "two", "two", "three", "four", "three", "five"]


def _template() -> str:
    tags_ = [{"Key": "sim2real", "Value": CHECK}]
    return json.dumps({
        "Resources": {
            # No TopicName / QueueName: CloudFormation must mint names carrying the .fifo suffix.
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {
                "FifoTopic": True, "ContentBasedDeduplication": True, "Tags": tags_}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"FifoQueue": True, "Tags": tags_}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage", "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}}}]},
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {"TopicArn": {"Ref": "Topic"}, "Protocol": "sqs",
                               "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]}},
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    })


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-named FIFO topic ends in .fifo with content-based deduplication, and a group
    of publishes with repeated bodies arrives once per distinct body, in order, with its group id.
    """
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    out = _create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sns-cfnfifo-"), _template())
    topic, queue_url = out["TopicArn"], out["QueueUrl"]

    assert topic.endswith(".fifo"), "a CloudFormation-named FIFO topic must end in .fifo"
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    assert (attrs.get("FifoTopic"), attrs.get("ContentBasedDeduplication")) == ("true", "true"), (
        f"the deployed topic reports FifoTopic={attrs.get('FifoTopic')!r}, "
        f"ContentBasedDeduplication={attrs.get('ContentBasedDeduplication')!r}")

    run_id = ctx.unique_name("sim2real-")
    group = ctx.unique_name("sim2real-g-")
    for body in _BODIES:
        sns.publish(TopicArn=topic, Message=f"{run_id}:{body}", MessageGroupId=group)
    expected = [f"{run_id}:{b}" for b in dict.fromkeys(_BODIES)]

    got: list[tuple[str, str]] = []
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and len(got) < len(expected):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   AttributeNames=["MessageGroupId"])
        for msg in resp.get("Messages", []):
            got.append((json.loads(msg["Body"])["Message"], msg["Attributes"]["MessageGroupId"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    # Drain once more so a duplicate that slipped through is seen, not left behind.
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3,
                               AttributeNames=["MessageGroupId"])
    for msg in resp.get("Messages", []):
        got.append((json.loads(msg["Body"])["Message"], msg["Attributes"]["MessageGroupId"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    assert [m for m, _ in got] == expected, (
        f"the queue must receive each distinct body once, in first-publish order; expected "
        f"{[e.split(':', 1)[1] for e in expected]!r}, got {[m.split(':', 1)[-1] for m, _ in got]!r}")
    assert {g for _, g in got} == {group}, "every delivered message must carry the published MessageGroupId"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
