"""events-target-role-without-trust-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "events-target-role-without-trust-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A target whose role does not trust events.amazonaws.com dead-letters the event with ERROR_CODE
    FAILED_TO_ASSUME_ROLE and the rule's ARN, while an identical target whose role trusts it delivers the
    event's marker to the Firehose stream's S3 destination."""
    events = ctx.client("events")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    bucket = _create_bucket(ctx, "sim2real-eb-neg-")
    fh_role_arn = _create_role(ctx, "firehose.amazonaws.com", _s3_write_policy(bucket))
    stream_name = ctx.unique_name("sim2real-eb-neg-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": fh_role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": "sim2real/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            "CompressionFormat": "UNCOMPRESSED",
        },
    )
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, stream_name))
    _wait_stream_active(firehose, stream_name)
    stream_arn = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]

    invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": stream_arn}
        ],
    }
    bad_role_arn = _create_role(ctx, "ec2.amazonaws.com", invoke_policy)
    good_role_arn = _create_role(ctx, "events.amazonaws.com", invoke_policy)

    dlq_url = _create_dlq_for_target(ctx, sqs)
    good_dlq_url = _create_dlq_for_target(ctx, sqs)

    rule_name = ctx.unique_name("sim2real-eb-rule-")
    source = ctx.unique_name("sim2real.source.")
    detail_type = "sim2real-test-event"
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    dlq_arn = _authorize_dlq_for_rule(sqs, dlq_url, rule_arn)
    good_dlq_arn = _authorize_dlq_for_rule(sqs, good_dlq_url, rule_arn)

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "bad", "Arn": stream_arn, "RoleArn": bad_role_arn, "DeadLetterConfig": {"Arn": dlq_arn}},
            {"Id": "good", "Arn": stream_arn, "RoleArn": good_role_arn, "DeadLetterConfig": {"Arn": good_dlq_arn}},
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["bad", "good"]))

    # IAM role trust propagation into EventBridge's target-invocation path is eventually
    # consistent, so a target invoked immediately after role creation can misfire even for
    # the correctly-trusted "good" role -- giving it its own DLQ makes that failure mode
    # observable instead of a silent drop. Retry the whole publish (bounded, fresh marker
    # each time) rather than trusting a fixed sleep to have waited long enough; a retry is
    # only warranted when the good target's own DLQ shows a transient rejection.
    marker, dlq_message, body = _fire_until_settled(
        events,
        sqs,
        s3,
        bucket,
        "sim2real/",
        dlq_url,
        good_dlq_url,
        source,
        detail_type,
        rule_arn,
        attempts=2,
        dlq_timeout_s=15.0,
        s3_timeout_s=240.0,
    )
    assert dlq_message["MessageAttributes"]["ERROR_CODE"]["StringValue"] == "FAILED_TO_ASSUME_ROLE"
    assert dlq_message["MessageAttributes"]["RULE_ARN"]["StringValue"] == rule_arn

    # positive control: the "good" target (correctly-trusted role) still delivers
    assert marker in body


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role_arn


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    """Delete the inline policy, then the role: DeleteRole refuses a role that still has policies."""
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _s3_write_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectAcl"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }


def _create_delivery_stream_with_retry(firehose, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 600.0) -> None:
    """DeleteDeliveryStream is asynchronous: wait until DescribeDeliveryStream answers ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
                "DeliveryStreamStatus"
            ]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still {status} {timeout_s}s after DeleteDeliveryStream")
        time.sleep(2)


def _wait_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} never became ACTIVE (last status={status})")


def _poll_s3_for_marker(s3, bucket: str, prefix: str, markers: list[str], timeout_s: float = 240.0):
    """The first (marker, body) of an S3 object holding any of ``markers``, or None at the deadline."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
            for marker in markers:
                if marker in body:
                    return marker, body
        time.sleep(5)
    return None


def _poll_for_dlq_message(sqs, queue_url: str, marker: str, timeout_s: float = 30.0) -> dict | None:
    """Poll for the dead-letter-queue message tied to `marker`, draining (and discarding)
    any stale message left behind by an earlier retried attempt. Returns None on timeout
    instead of raising, so the caller can decide whether to retry with a fresh event."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg
    return None


def _create_dlq_for_target(ctx, sqs) -> str:
    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-eb-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    return dlq_url


def _authorize_dlq_for_rule(sqs, dlq_url: str, rule_arn: str) -> str:
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=dlq_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventsToSendToDLQ",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": dlq_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    return dlq_arn


def _fire_until_settled(
    events,
    sqs,
    s3,
    bucket: str,
    prefix: str,
    dlq_url: str,
    good_dlq_url: str,
    source: str,
    detail_type: str,
    rule_arn: str,
    *,
    attempts: int,
    dlq_timeout_s: float,
    s3_timeout_s: float,
) -> tuple[str, dict, str]:
    """Publish a fresh event and wait for both legs to settle: the bad-role target's
    dead-letter-queue message (expected every time -- its trust mismatch is permanent,
    not propagation-dependent) and the good-role target's delivery to S3. A transient
    IAM-propagation misfire on the good role surfaces as either a message landing in
    ITS OWN dead-letter queue or as no S3 delivery within the window; either is grounds
    to retry with a fresh marker, bounded by `attempts`, rather than trusting a fixed
    sleep to have waited long enough before the one shot we get."""
    last_reason = None
    sent: list[str] = []
    for attempt in range(attempts):
        marker = f"{source}-{attempt}"
        put_resp = events.put_events(
            Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
        )
        assert put_resp["FailedEntryCount"] == 0, f"put_events rejected the entry: {put_resp}"
        sent.append(marker)

        dlq_message = _poll_for_dlq_message(sqs, dlq_url, marker, timeout_s=dlq_timeout_s)
        if dlq_message is None:
            last_reason = f"marker {marker}: no bad-role DLQ message within {dlq_timeout_s}s"
            continue

        # A retried good-role invocation can deliver an earlier attempt's event late, so any sent marker counts.
        found = _poll_s3_for_marker(s3, bucket, prefix, sent, timeout_s=s3_timeout_s)
        if found is not None:
            return found[0], dlq_message, found[1]

        good_dlq_message = _poll_for_dlq_message(sqs, good_dlq_url, marker, timeout_s=5.0)
        if good_dlq_message is not None:
            good_code = good_dlq_message["MessageAttributes"].get("ERROR_CODE", {}).get("StringValue")
            last_reason = f"marker {marker}: good-role target itself was rejected: {good_code}"
        else:
            last_reason = f"marker {marker}: no S3 delivery within {s3_timeout_s}s and no good-role DLQ message"

    raise AssertionError(f"target invocation never settled after {attempts} attempts (last: {last_reason})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
