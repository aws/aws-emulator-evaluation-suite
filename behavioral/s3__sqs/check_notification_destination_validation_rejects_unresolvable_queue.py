"""notification-destination-validation-rejects-unresolvable-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-destination-validation-rejects-unresolvable-queue"
GROUP = 'notifications'
SERVICES = ['s3', 'sqs']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects, versions, delete markers) then delete it; a failure raises."""
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    client.delete_bucket(Bucket=bucket)


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-xsvc-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return the (Error.Code, Error.Message) of its ClientError. A success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


def _drain_messages(sqs, queue_url, *, timeout_s=20.0):
    """Receive-and-delete every message that shows up within timeout_s; return their JSON bodies."""
    out = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if not messages:
            if out:
                break
            continue
        for msg in messages:
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:eventing",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration validates destinations at call time: a real queue is
    accepted and gets an s3:TestEvent; a nonexistent queue ARN is rejected with InvalidArgument and
    the bucket keeps its prior configuration.
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _new_bucket(ctx, s3)

    queue_name = ctx.unique_name("sim2real-xsvc-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    # IAM/SQS-policy propagation has no API to poll; retry the first use through it instead.
    deadline = time.monotonic() + 30.0
    last_code = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket,
                NotificationConfiguration={
                    "QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]
                },
            )
            last_code = None
            break
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            time.sleep(3)
    assert last_code is None, f"PutBucketNotificationConfiguration with a valid, policy-granting queue kept failing: {last_code!r}"

    # --- Positive control: the valid destination fires an s3:TestEvent with the documented shape.
    messages = _drain_messages(sqs, queue_url, timeout_s=20.0)
    test_events = [m for m in messages if isinstance(m, dict) and m.get("Event") == "s3:TestEvent"]
    assert test_events, f"no s3:TestEvent arrived after a valid PutBucketNotificationConfiguration; saw {messages!r}"
    event = test_events[0]
    assert event.get("Service") == "Amazon S3", f"TestEvent Service was {event.get('Service')!r}"
    assert event.get("Bucket") == bucket, f"TestEvent Bucket was {event.get('Bucket')!r}, want {bucket!r}"
    assert event.get("RequestId"), f"TestEvent carried no RequestId: {event!r}"
    assert event.get("HostId"), f"TestEvent carried no HostId: {event!r}"
    assert "Records" not in event, f"TestEvent carried a Records key: {event!r}; it is not an event-record envelope"

    # --- Break exactly one thing: an ARN naming a queue that was never created.
    missing_arn = queue_arn + "-missing"
    code, message = _error(lambda: s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [{"QueueArn": missing_arn, "Events": ["s3:ObjectCreated:*"]}]
        },
    ))
    assert code == "InvalidArgument", (
        f"PutBucketNotificationConfiguration against a nonexistent queue ARN raised {code!r}, "
        "want 'InvalidArgument'"
    )
    assert message == "Unable to validate the following destination configurations", (
        f"the unresolvable-destination refusal message is {message!r}")

    # The rejected call must not have replaced the bucket's (valid) configuration with anything new.
    current = s3.get_bucket_notification_configuration(Bucket=bucket)
    current_arns = [q["QueueArn"] for q in current.get("QueueConfigurations", [])]
    assert current_arns == [queue_arn], (
        f"after the rejected call, GetBucketNotificationConfiguration reports queues {current_arns!r}; "
        f"want the untouched valid configuration [{queue_arn!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
