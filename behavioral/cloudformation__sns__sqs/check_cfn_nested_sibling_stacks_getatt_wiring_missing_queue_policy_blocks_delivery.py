"""cfn-nested-sibling-stacks-getatt-wiring-missing-queue-policy-blocks-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-nested-sibling-stacks-getatt-wiring-missing-queue-policy-blocks-delivery"
GROUP = "nested-stacks-rejected"
SERVICES = ["cloudformation", "sns", "sqs"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _stack(cf, name):
    return cf.describe_stacks(StackName=name)["Stacks"][0]


def _wait_terminal(cf, name, *, timeout_s=600.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _stack(cf, name)
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s "
                f"(last={stack['StackStatus']!r})"
            )
        time.sleep(interval_s)


def _bucket(ctx, s3):
    name = ctx.unique_name("sim2real-cfn-sib-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _producer_template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


def _consumer_template(*, with_policy: bool) -> str:
    resources = {
        "Queue": {"Type": "AWS::SQS::Queue"},
        "Subscription": {
            "Type": "AWS::SNS::Subscription",
            "Properties": {
                "TopicArn": {"Ref": "TopicArn"},
                "Protocol": "sqs",
                "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                "RawMessageDelivery": True,
            },
        },
    }
    if with_policy:
        resources["QueuePolicy"] = {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": "Queue"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                        "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "TopicArn"}}},
                    }],
                },
            },
        }
        # Ordering the subscription after the policy keeps the first publish from racing the
        # policy that admits it.
        resources["Subscription"]["DependsOn"] = "QueuePolicy"
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"TopicArn": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    })


def _parent_template(producer_url, good_url, bad_url) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Producer": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {"TemplateURL": producer_url},
            },
            "Good": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": good_url,
                    "Parameters": {"TopicArn": {"Fn::GetAtt": ["Producer", "Outputs.TopicArn"]}},
                },
            },
            "Bad": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": bad_url,
                    "Parameters": {"TopicArn": {"Fn::GetAtt": ["Producer", "Outputs.TopicArn"]}},
                },
            },
        },
    })


def _url(region: str, bucket: str, key: str) -> str:
    return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"


def _delete_stack_and_wait(cf, stack_id, *, timeout_s=600.0, interval_s=5.0):
    """Delete the stack by id and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _stack(cf, stack_id)
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() >= deadline:
            raise RuntimeError(
                f"stack {stack_id} teardown ended {stack['StackStatus']!r}: "
                f"{stack.get('StackStatusReason')!r}"
            )
        time.sleep(interval_s)


def _receive(sqs, url, *, wait_s=5):
    msgs = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    ).get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return [m["Body"] for m in msgs]


def _deliver_and_wait(sns, sqs, topic_arn, queue_url, marker, *, timeout_s=90.0):
    """Publish ``marker`` to the topic, re-publishing until it is seen in ``queue_url``."""
    deadline = time.monotonic() + timeout_s
    start = time.monotonic()
    while time.monotonic() < deadline:
        sns.publish(TopicArn=topic_arn, Message=marker)
        if marker in _receive(sqs, queue_url):
            return time.monotonic() - start
        time.sleep(1.0)
    raise AssertionError(f"{marker!r} never reached {queue_url} within {timeout_s}s")


@tags(
    "axis:negative-delivery", "cap:c3", "cap:c7", "concern:deploy", "concern:eventing",
    "concern:negative-classes", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """Two sibling nested stacks each resolve a producer sibling's topic ARN via
    Fn::GetAtt Producer.Outputs.TopicArn; the sibling whose queue has no SQS policy for the SNS
    principal never receives a publish, while the sibling that has one receives it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-nested-stacks.html
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3)

    for key, body in (
        ("producer.json", _producer_template()),
        ("good.json", _consumer_template(with_policy=True)),
        ("bad.json", _consumer_template(with_policy=False)),
    ):
        s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
        ctx.on_cleanup(lambda k=key: s3.delete_object(Bucket=bucket, Key=k))

    producer_url = _url(ctx.region, bucket, "producer.json")
    good_url = _url(ctx.region, bucket, "good.json")
    bad_url = _url(ctx.region, bucket, "bad.json")

    stack_name = ctx.unique_name("sim2real-cfn-sib-root-")
    root_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=_parent_template(producer_url, good_url, bad_url),
        Tags=_TAGS,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, root_id))

    root = _wait_terminal(cf, root_id, timeout_s=300.0)
    assert root["StackStatus"] == "CREATE_COMPLETE", (
        f"the root must reach CREATE_COMPLETE, got {root['StackStatus']!r}: "
        f"{root.get('StackStatusReason')!r}"
    )

    def physical(logical_id):
        return cf.describe_stack_resource(StackName=root_id, LogicalResourceId=logical_id)[
            "StackResourceDetail"
        ]["PhysicalResourceId"]

    producer_id, good_id, bad_id = physical("Producer"), physical("Good"), physical("Bad")

    topic_arn = {
        o["OutputKey"]: o["OutputValue"] for o in _stack(cf, producer_id).get("Outputs", [])
    }["TopicArn"]
    # The owning service, not CloudFormation's view, confirms the topic is real.
    topic_attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert topic_attrs["TopicArn"] == topic_arn, topic_attrs

    good_queue = {
        o["OutputKey"]: o["OutputValue"] for o in _stack(cf, good_id).get("Outputs", [])
    }["QueueUrl"]
    bad_queue = {
        o["OutputKey"]: o["OutputValue"] for o in _stack(cf, bad_id).get("Outputs", [])
    }["QueueUrl"]
    # The owning service confirms both queues are real, independent of the stacks' own view.
    for url in (good_queue, bad_queue):
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
        assert "QueueArn" in attrs, (
            f"{url} has no QueueArn via SQS's own GetQueueAttributes: {attrs!r}"
        )

    # The sibling with no policy still has a confirmed subscription, so an empty queue below can
    # only be the missing permission, not a missing or unconfirmed subscription.
    bad_arn = sqs.get_queue_attributes(QueueUrl=bad_queue, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    subs = [
        x for x in sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
        if x["Protocol"] == "sqs" and x["Endpoint"] == bad_arn
    ]
    assert len(subs) == 1, f"SNS lists {len(subs)} sqs subscriptions to {bad_arn}, expected 1"
    pending = sns.get_subscription_attributes(SubscriptionArn=subs[0]["SubscriptionArn"])[
        "Attributes"]["PendingConfirmation"]
    assert pending == "false", f"the policy-less sibling's subscription is pending: {pending!r}"

    marker = ctx.unique_name("marker-")
    latency = _deliver_and_wait(sns, sqs, topic_arn, good_queue, marker)

    # The positive control sets the absence window: 3x its latency, floored at 10s.
    window = max(10.0, 3.0 * latency)
    deadline = time.monotonic() + window
    seen: list[str] = []
    while time.monotonic() < deadline:
        sns.publish(TopicArn=topic_arn, Message=marker)
        seen.extend(_receive(sqs, bad_queue, wait_s=2))
    assert seen == [], (
        f"the sibling with no SQS queue policy for sns.amazonaws.com received {seen!r} over "
        f"{window:.0f}s — a missing permission must block delivery, not be bypassed"
    )

    # Rule out a broken queue (a typo in the URL would also look empty): sending directly,
    # bypassing SNS, must still reach the same queue the SNS publishes above could not.
    probe = ctx.unique_name("probe-")
    sqs.send_message(QueueUrl=bad_queue, MessageBody=probe)
    direct = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and probe not in direct:
        direct.extend(_receive(sqs, bad_queue, wait_s=3))
    assert probe in direct, (
        f"a message sent directly to the blocked sibling's own queue never arrived ({direct!r}) "
        f"— the queue itself, not just the SNS permission, would be the real defect"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
