"""platform-application-event-endpoint-created-notifies-configured-topic."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "platform-application-event-endpoint-created-notifies-configured-topic"
GROUP = "eventing"
SERVICES = ["sns", "sqs"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:eventing", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A platform application's EventEndpointCreated topic receives an EndpointCreated
    notification naming the EndpointArn when CreatePlatformEndpoint adds an endpoint.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-appevt-t-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sns-appevt-q-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    deadline = time.monotonic() + 60.0
    pending = sns.get_subscription_attributes(
        SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
    while pending != "false":
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subscription never left PendingConfirmation; last value {pending!r}")
        time.sleep(1.0)
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")

    app_name = ctx.unique_name("sim2real-behav-sns-appevt-app-")
    app_arn = sns.create_platform_application(
        Name=app_name,
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": "sim2real-fake-api-key",
            "PlatformCredential": "sim2real-fake-secret-key",
            "EventEndpointCreated": topic_arn,
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    app_attrs = sns.get_platform_application_attributes(
        PlatformApplicationArn=app_arn)["Attributes"]
    assert app_attrs.get("EventEndpointCreated") == topic_arn, (
        f"positive control: expected EventEndpointCreated to read back as the configured topic "
        f"{topic_arn!r}, got {app_attrs.get('EventEndpointCreated')!r}"
    )

    channel_id = str(uuid.uuid4().int)[:16]
    endpoint_arn = sns.create_platform_endpoint(
        PlatformApplicationArn=app_arn, Token=channel_id,
        Attributes={"ChannelId": channel_id, "UserId": "sim2real-fake-baidu-user"},
    )["EndpointArn"]
    ctx.on_cleanup(lambda: sns.delete_endpoint(EndpointArn=endpoint_arn))

    deadline = time.monotonic() + 90.0
    notification = None
    while notification is None:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            parsed = json.loads(msg["Body"])
            if parsed.get("EndpointArn") == endpoint_arn:
                notification = parsed
        if notification is None and time.monotonic() >= deadline:
            raise AssertionError(
                f"no EventEndpointCreated notification naming {endpoint_arn!r} arrived within 90s")

    assert notification.get("EventType") == "EndpointCreated", (
        f"expected EventType 'EndpointCreated', got {notification.get('EventType')!r} "
        f"in {notification!r}"
    )
    assert notification.get("EndpointArn") == endpoint_arn, (
        f"expected EndpointArn {endpoint_arn!r}, got {notification.get('EndpointArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
