"""notification-fifo-destination-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-fifo-destination-rejected"
GROUP = "notifications"
SERVICES = ["s3"]


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket, register teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _delete_queue(sqs, queue_url):
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _new_queue(ctx, sqs, bucket, *, fifo: bool):
    """Create a uniquely-named queue (FIFO or standard), permit S3 to send to it, tag it,
    register teardown, return (queue_url, queue_arn)."""
    name = ctx.unique_name("sim2real-behav-q-")
    if fifo:
        name += ".fifo"
    attrs = {"FifoQueue": "true", "ContentBasedDeduplication": "true"} if fifo else {}
    kwargs = {"QueueName": name}
    if attrs:
        kwargs["Attributes"] = attrs
    queue_url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, queue_url))
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": CHECK})
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
                }
            ],
        }
    )
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": policy})
    return queue_url, queue_arn


def _delete_topic(sns, topic_arn):
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _new_topic(ctx, sns, bucket, *, fifo: bool):
    """Create a uniquely-named topic (FIFO or standard), permit S3 to publish to it, tag it,
    register teardown, return the topic ARN."""
    name = ctx.unique_name("sim2real-behav-t-")
    if fifo:
        name += ".fifo"
    kwargs = {"Name": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if fifo:
        kwargs["Attributes"] = {"FifoTopic": "true"}
    topic_arn = sns.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: _delete_topic(sns, topic_arn))
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                    "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
                }
            ],
        }
    )
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy)
    return topic_arn


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, Error.ArgumentName, Error.ArgumentValue) of
    the ClientError it raises. An unexpected success raises, so acceptance never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), err.get("ArgumentName"), err.get("ArgumentValue")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration refuses a FIFO SQS queue destination and a FIFO SNS
    topic destination with the exact error, and applies neither; a standard queue or topic with
    the same permission is accepted."""
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    bucket = _new_bucket(ctx, s3)

    # ---- positive control: a standard (non-FIFO) queue is accepted ----
    _, ok_queue_arn = _new_queue(ctx, sqs, bucket, fifo=False)
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"QueueConfigurations": [{"QueueArn": ok_queue_arn, "Events": ["s3:ObjectCreated:*"]}]},
    )
    control = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert [c["QueueArn"] for c in control.get("QueueConfigurations", [])] == [ok_queue_arn], (
        f"positive control: a standard queue must be accepted, got {control}"
    )
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})

    # ---- break exactly one thing: the SAME permission, on a FIFO queue ----
    _, fifo_queue_arn = _new_queue(ctx, sqs, bucket, fifo=True)
    code, message, arg_name, arg_value = _error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration={"QueueConfigurations": [{"QueueArn": fifo_queue_arn, "Events": ["s3:ObjectCreated:*"]}]},
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a FIFO queue destination, got {code!r}"
    assert message == "FIFO SQS queues are not supported.", message
    assert arg_name == "Queue", f"expected ArgumentName 'Queue', got {arg_name!r}"
    assert arg_value == fifo_queue_arn, f"expected ArgumentValue {fifo_queue_arn!r}, got {arg_value!r}"
    after_queue = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not after_queue.get("QueueConfigurations"), (
        f"a rejected PutBucketNotificationConfiguration must not partially apply, got {after_queue}"
    )

    # ---- positive control: a standard (non-FIFO) topic is accepted ----
    ok_topic_arn = _new_topic(ctx, sns, bucket, fifo=False)
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"TopicConfigurations": [{"TopicArn": ok_topic_arn, "Events": ["s3:ObjectCreated:*"]}]},
    )
    control2 = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert [c["TopicArn"] for c in control2.get("TopicConfigurations", [])] == [ok_topic_arn], (
        f"positive control: a standard topic must be accepted, got {control2}"
    )
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})

    # ---- break exactly one thing: the SAME permission, on a FIFO topic ----
    fifo_topic_arn = _new_topic(ctx, sns, bucket, fifo=True)
    code2, message2, arg_name2, arg_value2 = _error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration={"TopicConfigurations": [{"TopicArn": fifo_topic_arn, "Events": ["s3:ObjectCreated:*"]}]},
        )
    )
    assert code2 == "InvalidArgument", f"expected InvalidArgument for a FIFO topic destination, got {code2!r}"
    assert message2 == (
        "The ARN failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "^arn:aws[\\p{Alpha}\\-]*:sns:[\\p{Alnum}\\-]+:[\\p{Digit}]{12}:[\\p{Alnum}\\-_]{1,256}$"
    ), message2
    assert arg_name2 == "Topic", f"expected ArgumentName 'Topic', got {arg_name2!r}"
    assert arg_value2 == fifo_topic_arn, f"expected ArgumentValue {fifo_topic_arn!r}, got {arg_value2!r}"
    after_topic = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not after_topic.get("TopicConfigurations"), (
        f"a rejected PutBucketNotificationConfiguration must not partially apply, got {after_topic}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
