"""firehose-subscription-writes-each-notification-envelope-into-the-stream-bucket."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-subscription-writes-each-notification-envelope-into-the-stream-bucket"
GROUP = "firehose-delivery"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A firehose subscription writes one newline-terminated JSON envelope per matching publish
    (Type, MessageId, TopicArn, Subject, Message, attributes as {Type, Value}) to the stream's
    bucket, and nothing for a publish its filter policy rejects.
    """
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-fh-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    bucket, stream_arn = _delivery_stream(ctx)
    role_arn = _subscription_role(ctx, stream_arn, grant=True)

    sub = _subscribe(ctx, topic, stream_arn, role_arn, {
        "FilterPolicy": json.dumps({"kind": ["keep"]})})
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert (attrs.get("Protocol"), attrs.get("Endpoint"), attrs.get("SubscriptionRoleArn"),
            attrs.get("PendingConfirmation")) == ("firehose", stream_arn, role_arn, "false"), (
        f"the firehose subscription must be confirmed at once and keep its endpoint and role; got "
        f"Protocol {attrs.get('Protocol')!r}, PendingConfirmation {attrs.get('PendingConfirmation')!r}, "
        f"endpoint matches={attrs.get('Endpoint') == stream_arn}, role matches={attrs.get('SubscriptionRoleArn') == role_arn}")

    _warm_up(ctx, topic, bucket)

    published = {}
    for i in range(3):
        body = ctx.unique_name(f"sim2real-fh-{i}-")
        mid = sns.publish(TopicArn=topic, Message=body, Subject=f"subject {i}", MessageAttributes={
            "kind": {"DataType": "String", "StringValue": "keep"},
            "n": {"DataType": "Number", "StringValue": str(i)}})["MessageId"]
        published[mid] = (body, i)
    dropped = ctx.unique_name("sim2real-fh-dropped-")
    sns.publish(TopicArn=topic, Message=dropped,
                MessageAttributes={"kind": {"DataType": "String", "StringValue": "drop"}})

    records = _records(ctx, bucket, lambda rs: set(published) <= {r.get("MessageId") for r in rs}, 240)
    got = {r.get("MessageId"): r for r in records}
    assert set(published) <= set(got), (
        f"every matching notification must reach the stream's bucket; found "
        f"{len(set(published) & set(got))} of {len(published)} in {len(records)} record(s)")
    for mid, (body, i) in published.items():
        rec = got[mid]
        assert (rec.get("Type"), rec.get("TopicArn"), rec.get("Message"), rec.get("Subject")) == (
            "Notification", topic, body, f"subject {i}"), (
            f"record {i} must be the notification envelope; got Type {rec.get('Type')!r}, "
            f"Subject {rec.get('Subject')!r}, Message matches={rec.get('Message') == body}")
        assert rec.get("MessageAttributes") == {
            "kind": {"Type": "String", "Value": "keep"}, "n": {"Type": "Number", "Value": str(i)}}, (
            f"record {i} carries MessageAttributes {rec.get('MessageAttributes')!r}")
    assert all(r.get("Message") != dropped for r in records), (
        "a notification the filter policy rejects was written to the stream")
    real = [r for r in records if not str(r.get("Message", "")).startswith("sim2real-warm-")]
    assert len(real) == len(published), (
        f"the bucket must hold exactly the {len(published)} matching notifications; it holds {len(real)}")


def _warm_up(ctx, topic: str, bucket: str) -> None:
    """Publish until one record reaches the bucket: SNS can refuse to act as a just-created
    subscription role for a while, and nothing exposes when it may."""
    sns = ctx.client("sns")
    deadline = time.monotonic() + 240
    while True:
        token = ctx.unique_name("sim2real-warm-")
        sns.publish(TopicArn=topic, Message=token,
                    MessageAttributes={"kind": {"DataType": "String", "StringValue": "keep"}})
        if any(r.get("Message") == token for r in _records(ctx, bucket, lambda rs: any(
                r.get("Message") == token for r in rs), 40)):
            return
        assert time.monotonic() < deadline, "no record reached the stream's bucket while warming up"


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
    """Every record under the stream's prefix, polled until ``want(records)`` holds or the
    deadline passes. Envelope records are newline-terminated, so every object must end in a
    newline and hold one JSON document per line."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while True:
        records: list[dict] = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="sns/"):
            for obj in page.get("Contents", []):
                data = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8")
                assert data.endswith("\n"), f"a stream object does not end in a newline: {data[-80:]!r}"
                records.extend(json.loads(line) for line in data[:-1].split("\n"))
        if want(records) or time.monotonic() >= deadline:
            return records
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
