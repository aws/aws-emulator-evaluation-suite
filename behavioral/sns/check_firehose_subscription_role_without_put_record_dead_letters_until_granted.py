"""firehose-subscription-role-without-put-record-dead-letters-until-granted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-subscription-role-without-put-record-dead-letters-until-granted"
GROUP = "firehose-delivery"
SERVICES = ["sns"]


@tags("axis:negative-delivery", "cap:c2", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A firehose subscription whose role may not put records writes nothing to the stream and
    dead-letters the notification envelope; once the role is granted PutRecord, the next
    notification is written once to the stream's bucket and is not dead-lettered.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fhperm-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    bucket, stream_arn = _delivery_stream(ctx)
    role_arn = _subscription_role(ctx, stream_arn, grant=False)
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-dlq-"),
                               tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": dlq_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})
    _subscribe(ctx, topic, stream_arn, role_arn,
               {"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn})})

    refused = ctx.unique_name("sim2real-fhperm-refused-")
    mid = sns.publish(TopicArn=topic, Message=refused)["MessageId"]
    dead = _drain_until(sqs, dlq_url, lambda d: any(e.get("MessageId") == mid for e in d), 240)
    letter = [e for e in dead if e.get("MessageId") == mid]
    assert len(letter) == 1, (
        f"the notification the role could not put must be dead-lettered once; found {len(letter)} "
        f"among {len(dead)} dead letter(s)")
    assert (letter[0].get("Type"), letter[0].get("TopicArn"), letter[0].get("Message")) == (
        "Notification", topic, refused), (
        f"the dead letter must be the notification envelope; got Type {letter[0].get('Type')!r}, "
        f"Message matches={letter[0].get('Message') == refused}")
    assert _records(ctx, bucket, lambda rs: False, 10) == [], (
        "the stream's bucket received a record although the subscription role may not put one")

    # Positive control: grant the role, and the same subscription delivers.
    role_name = role_arn.rsplit("/", 1)[1]
    iam.put_role_policy(RoleName=role_name, PolicyName="access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch",
                                          "firehose:DescribeDeliveryStream"],
            "Resource": stream_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="access"))
    deadline = time.monotonic() + 240
    while True:
        body = ctx.unique_name("sim2real-fhperm-ok-")
        ok = sns.publish(TopicArn=topic, Message=body)["MessageId"]
        recs = _records(ctx, bucket, lambda rs: any(r.get("MessageId") == ok for r in rs), 40)
        if any(r.get("MessageId") == ok for r in recs):
            break
        # IAM propagation: no API reports when the new role policy becomes effective.
        assert time.monotonic() < deadline, "after granting the role, no notification reached the stream"
    late = _drain_until(sqs, dlq_url, lambda d: False, 6)
    assert all(e.get("MessageId") != ok for e in late), "a notification the stream received was also dead-lettered"
    written = [r for r in recs if r.get("MessageId") == ok]
    assert len(written) == 1 and written[0].get("Message") == body, (
        f"the granted notification must be written once, as published; found {len(written)}")


def _drain_until(sqs, url: str, done, timeout_s: float) -> list[dict]:
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while True:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", []):
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if done(out) or time.monotonic() >= deadline:
            return out


# A DirectPut delivery stream with zero buffering writes into a bucket this check creates;
# its role may only write that bucket. The subscription role may only put records into that
# stream.

def _trust(service: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def _role(ctx, service: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sns-fh-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_trust(service),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="access", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="access"))
    return arn


def _empty_and_delete_bucket(s3, bucket: str):
    def _fn():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
    return _fn


def _delivery_stream(ctx) -> tuple[str, str]:
    """(bucket name, ACTIVE delivery stream ARN)."""
    s3 = ctx.client("s3")
    fh = ctx.client("firehose")
    bucket = ctx.unique_name("sim2real-behav-sns-fh-")
    kwargs = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(_empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    role_arn = _role(ctx, "firehose.amazonaws.com", [{
        "Effect": "Allow",
        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket",
                   "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]}])
    name = ctx.unique_name("sim2real-behav-sns-fh-")
    deadline = time.monotonic() + 120
    while True:
        try:
            arn = fh.create_delivery_stream(
                DeliveryStreamName=name, DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}", "Prefix": "sns/",
                    "ErrorOutputPrefix": "errors/",
                    "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1}},
                Tags=[{"Key": "sim2real", "Value": CHECK}])["DeliveryStreamARN"]
            break
        except ClientError as exc:
            # A just-created role is not yet assumable by Firehose; nothing to poll.
            if exc.response["Error"]["Code"] != "InvalidArgumentException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))
    deadline = time.monotonic() + 240
    while True:
        status = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return bucket, arn
        assert status == "CREATING" and time.monotonic() < deadline, f"delivery stream is {status!r}"
        time.sleep(5)


def _subscription_role(ctx, stream_arn: str, *, grant: bool) -> str:
    statements = [{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch",
                                                 "firehose:DescribeDeliveryStream"],
                   "Resource": stream_arn}] if grant else []
    return _role(ctx, "sns.amazonaws.com", statements)


def _subscribe(ctx, topic: str, stream_arn: str, role_arn: str, extra: dict | None = None) -> str:
    """Subscribe the stream as a principal allowed to pass ``role_arn`` (Subscribe checks the
    caller's iam:PassRole on the subscription role)."""
    sns = ctx.client("sns")
    caller = _subscriber(ctx, topic, role_arn)
    deadline = time.monotonic() + 90
    while True:
        try:
            sub = caller.subscribe(TopicArn=topic, Protocol="firehose", Endpoint=stream_arn,
                                   ReturnSubscriptionArn=True,
                                   Attributes={"SubscriptionRoleArn": role_arn, **(extra or {})})["SubscriptionArn"]
            break
        except ClientError as exc:
            # The subscriber's new identity policy propagates; nothing to poll.
            if exc.response["Error"]["Code"] != "AuthorizationError" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    return sub


def _subscriber(ctx, topic: str, role_arn: str):
    """An SNS client signed as a role this check creates, which may subscribe to ``topic``
    and pass ``role_arn``."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-sns-fhsub-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole"}]}), Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="subscribe", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sns:Subscribe", "Resource": topic},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": role_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="subscribe"))
    deadline = time.monotonic() + 90
    while True:
        try:
            creds = sts.assume_role(RoleArn=arn, RoleSessionName="sim2real-subscriber")["Credentials"]
            break
        except ClientError as exc:
            # A just-created role's trust policy propagates; nothing to poll.
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return ctx.client("sns", creds={"aws_access_key_id": creds["AccessKeyId"],
                                    "aws_secret_access_key": creds["SecretAccessKey"],
                                    "aws_session_token": creds["SessionToken"]})


def _records(ctx, bucket: str, want, timeout_s: float) -> list[dict]:
    """Every record under the stream's prefix, one JSON document per line, polled until
    ``want(records)`` holds or the deadline passes."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while True:
        records: list[dict] = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="sns/"):
            for obj in page.get("Contents", []):
                data = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
                records.extend(json.loads(line) for line in data.splitlines() if line.strip())
        if want(records) or time.monotonic() >= deadline:
            return records
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
