"""notification-invalid-destination-rejected."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "notification-invalid-destination-rejected"
GROUP = 'notifications'
SERVICES = ['s3']

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
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _err_code(fn):
    """Call fn(); return botocore (Code, Message) on a ClientError.
    An unexpected success raises, so accepting refused input cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_queue(sqs, queue_url):
    """Best-effort SQS queue teardown."""
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _new_queue(ctx, sqs, prefix):
    """Create a uniquely-named, tagged queue, register delete teardown, return its URL."""
    queue_url = sqs.create_queue(QueueName=ctx.unique_name(prefix))["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue(sqs, queue_url))
    sqs.tag_queue(QueueUrl=queue_url, Tags={"sim2real": CHECK})
    return queue_url


def _allow_s3_send_policy(queue_arn, bucket):
    return json.dumps(
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration targeting an SQS queue that denies S3 SendMessage is
    rejected with InvalidArgument and applies nothing; a permitted twin queue is accepted, and
    granting the permission on the same queue makes the identical call succeed."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    sqs = ctx.client("sqs")

    # ---- positive control: an otherwise-identical queue WITH the permission is accepted ----
    ok_queue_url = _new_queue(ctx, sqs, "sim2real-behav-ok-policy-queue-")
    ok_queue_arn = sqs.get_queue_attributes(QueueUrl=ok_queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=ok_queue_url, Attributes={"Policy": _allow_s3_send_policy(ok_queue_arn, bucket)}
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"QueueConfigurations": [{"QueueArn": ok_queue_arn, "Events": ["s3:ObjectCreated:*"]}]},
    )
    control = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert [c["QueueArn"] for c in control.get("QueueConfigurations", [])] == [ok_queue_arn], (
        f"positive control: a queue WITH S3-SendMessage permission must be accepted, got {control}"
    )
    # clear it back out so the negative leg's effect-absent read below starts from a clean slate
    s3.put_bucket_notification_configuration(Bucket=bucket, NotificationConfiguration={})
    cleared = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not cleared.get("QueueConfigurations"), (
        f"expected the notification config cleared before the negative leg, got {cleared}"
    )

    # ---- break exactly one thing: an otherwise-identical queue with NO permission policy ----
    queue_url = _new_queue(ctx, sqs, "sim2real-behav-no-policy-queue-")
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    # deliberately NOT setting a resource policy that allows s3.amazonaws.com

    code, message = _err_code(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration={
                "QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]
            },
        )
    )
    assert code == "InvalidArgument", (
        f"expected InvalidArgument for a queue with no S3-SendMessage permission, got {code!r}"
    )
    assert message == "Unable to validate the following destination configurations", message

    # the bucket must have NO notification configuration as a result of the rejected call
    got = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert not got.get("QueueConfigurations"), (
        f"a rejected PutBucketNotificationConfiguration must not partially apply, got {got}"
    )

    # ---- restore: granting the SAME queue the missing permission makes the identical call succeed ----
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": _allow_s3_send_policy(queue_arn, bucket)}
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]},
    )
    restored = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert [c["QueueArn"] for c in restored.get("QueueConfigurations", [])] == [queue_arn], (
        f"the identical call must succeed once the missing permission is granted, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
