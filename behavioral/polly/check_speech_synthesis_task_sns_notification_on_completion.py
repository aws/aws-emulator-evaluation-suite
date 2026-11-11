"""speech-synthesis-task-sns-notification-on-completion."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "speech-synthesis-task-sns-notification-on-completion"
GROUP = "event-propagation"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A speech synthesis task with an SnsTopicArn actually publishes a completion
    notification carrying the real TaskId and a completed status -- observed
    end-to-end through an SQS subscriber, not merely accepted at submission time."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)
    topic_arn, queue_url = _wire_topic_to_queue(ctx)

    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="Notify me when this synthesis task finishes.",
        VoiceId="Matthew",
        SnsTopicArn=topic_arn,
    )["SynthesisTask"]
    task_id = started["TaskId"]

    messages = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=180.0)
    assert len(messages) == 1, f"expected exactly 1 queued message, got {len(messages)}"
    envelope = messages[0]["body"]
    assert isinstance(envelope, dict) and envelope.get("Type") == "Notification", (
        f"expected a raw SNS Notification envelope, got: {envelope!r}"
    )
    assert envelope.get("TopicArn") == topic_arn, (
        f"expected TopicArn {topic_arn}, got {envelope.get('TopicArn')}"
    )
    payload = envelope.get("Message", "")

    assert task_id in payload, f"task id {task_id} not present in notification: {payload}"
    assert "completed" in payload.lower(), f"no completion status in notification: {payload}"


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-sns-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint for its own region.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _wire_topic_to_queue(ctx: Any) -> tuple[str, str]:
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-polly-topic-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-polly-queue-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return topic_arn, queue_url


def _wait_for_messages(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0):
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)} in {timeout_s}s")
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
