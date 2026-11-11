"""create-trail-sns-topic-without-policy-fails."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":  # S3 rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (with a policy-ready bucket unless S3BucketName is given) and its teardown."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


def _create_notification_topic(ctx, sns, topic_name):
    """Create a bare SNS topic (default owner-only policy) and register teardown."""
    arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _allow_cloudtrail_publish(sns, topic_arn, account_id):
    """Attach the SNS access policy CloudTrail needs to publish notifications."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "__default_statement_ID",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["SNS:Publish", "SNS:GetTopicAttributes", "SNS:Subscribe"],
                "Resource": topic_arn,
                "Condition": {"StringEquals": {"AWS:SourceOwner": account_id}},
            },
            {
                "Sid": "AWSCloudTrailSNSPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
        ],
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
    )


CHECK = "create-trail-sns-topic-without-policy-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudTrail refuses a bare SNS topic (InsufficientSnsTopicPolicyException) or a malformed name,
    storing nothing and creating no orphan trail; once the publish policy is attached it succeeds.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-permissions-for-sns-notifications.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    sns = ctx.client("sns")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: an ordinary trail with no notification topic.
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name)
    minted_arn = created["TrailARN"]
    assert "SnsTopicARN" not in created, created.get("SnsTopicARN")

    def assert_no_topic():
        trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
        assert trail["TrailARN"] == minted_arn, trail["TrailARN"]
        assert "SnsTopicARN" not in trail, trail.get("SnsTopicARN")
        assert "SnsTopicName" not in trail, trail.get("SnsTopicName")
        return trail

    assert_no_topic()

    topic_name = ctx.unique_name("sim2real-behav-ct-sns-")
    topic_arn = _create_notification_topic(ctx, sns, topic_name)

    # Break exactly one thing: the topic exists but does not grant CloudTrail publish.
    code, msg = _error(lambda: ct.update_trail(Name=name, SnsTopicName=topic_name))
    assert code == "InsufficientSnsTopicPolicyException", code
    assert msg == "SNS Topic does not exist or the topic policy is incorrect!", msg
    # Effect absent: the refused update stored no topic on the trail.
    assert_no_topic()

    # A malformed topic name is a name-grammar refusal, distinct from the policy refusal.
    code, msg = _error(lambda: ct.update_trail(Name=name, SnsTopicName="bad topic name!"))
    assert code == "InvalidSnsTopicNameException", code
    assert msg == "Invalid SNS topic name: bad topic name! is found!", msg
    assert_no_topic()

    # CreateTrail applies the same validation and must not leave an orphan trail.
    bucket = _call(lambda: ct.get_trail(Name=name))["Trail"]["S3BucketName"]
    orphan = ctx.unique_name("sim2real-behav-ct-trail-")
    code, msg = _error(
        lambda: ct.create_trail(Name=orphan, S3BucketName=bucket, SnsTopicName=topic_name)
    )
    assert code == "InsufficientSnsTopicPolicyException", code
    assert msg == "SNS Topic does not exist or the topic policy is incorrect!", msg
    orphan_get_code, orphan_get_msg = _error(lambda: ct.get_trail(Name=orphan))
    assert orphan_get_code == "TrailNotFoundException", orphan_get_code
    assert orphan_get_msg == f"Unknown trail: {orphan} for the user: {account}", orphan_get_msg
    orphan_list = _call(lambda: ct.describe_trails(trailNameList=[orphan]))["trailList"]
    assert orphan_list == [], orphan_list

    # Control: with the publish policy attached the identical call succeeds, so the refusals
    # above were about the policy. The retry covers SNS policy propagation delay.
    _allow_cloudtrail_publish(sns, topic_arn, account)
    updated = _call(
        lambda: ct.update_trail(Name=name, SnsTopicName=topic_name),
        retry_codes=("ThrottlingException", "InsufficientSnsTopicPolicyException"),
        attempts=8,
    )
    assert updated["SnsTopicARN"] == topic_arn, (updated.get("SnsTopicARN"), topic_arn)

    trail = _call(lambda: ct.get_trail(Name=name))["Trail"]
    assert trail["SnsTopicARN"] == topic_arn, (trail.get("SnsTopicARN"), topic_arn)
    assert trail["TrailARN"] == minted_arn, trail["TrailARN"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
