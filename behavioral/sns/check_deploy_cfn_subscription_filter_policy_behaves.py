"""deploy-cfn-subscription-filter-policy-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-subscription-filter-policy-behaves"
GROUP = "state-machine"
SERVICES = ["sns"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed subscription with a FilterPolicy only delivers
    messages matching the filter; verified by publishing matching and
    non-matching messages against the live, deployed resources."""
    template = {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Queue": {"Type": "AWS::SQS::Queue"},
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
                    "RawMessageDelivery": "true",
                    "FilterPolicy": {"color": ["red"]},
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "SubscriptionArn": {"Value": {"Ref": "Subscription"}},
        },
    }

    outputs, stack_name = _deploy_cfn(ctx, json.dumps(template))
    topic_arn = outputs["TopicArn"]
    queue_url = outputs["QueueUrl"]
    subscription_arn = outputs["SubscriptionArn"]

    sns = ctx.client("sns")
    sub_attrs = sns.get_subscription_attributes(SubscriptionArn=subscription_arn)["Attributes"]
    assert json.loads(sub_attrs["FilterPolicy"]) == {"color": ["red"]}, (
        f"expected FilterPolicy {{'color': ['red']}}, got {sub_attrs['FilterPolicy']}"
    )

    match_token = ctx.unique_name("sim2real-match-")
    nomatch_token = ctx.unique_name("sim2real-nomatch-")

    sns.publish(
        TopicArn=topic_arn,
        Message=nomatch_token,
        MessageAttributes={"color": {"DataType": "String", "StringValue": "blue"}},
    )
    sns.publish(
        TopicArn=topic_arn,
        Message=match_token,
        MessageAttributes={"color": {"DataType": "String", "StringValue": "red"}},
    )

    bodies = _drain_queue(ctx, queue_url, timeout_s=30.0)
    assert match_token in bodies, f"matching message never delivered: {bodies}"
    assert nomatch_token not in bodies, f"non-matching message was delivered: {bodies}"

    _delete_stack_and_wait(ctx, stack_name)
    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=subscription_arn))
    assert code == "NotFound", (
        f"subscription still readable after CFN stack teardown: code={code}"
    )
    assert message == "Subscription does not exist", (
        f"unexpected NotFound message reading the torn-down subscription: {message!r}"
    )


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _deploy_cfn(ctx, template_body: str) -> tuple[dict, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-sns-cfn-")

    def _cleanup():
        # Best-effort safety net: the happy path already deletes the stack (and
        # asserts it) in the body above. This only fires if the body raised first.
        try:
            _delete_stack_and_wait(ctx, stack_name)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    return outputs, stack_name


def _drain_queue(ctx, queue_url: str, timeout_s: float = 30.0) -> list[str]:
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if not msgs:
            continue
        for msg in msgs:
            bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
