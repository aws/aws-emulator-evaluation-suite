"""eventbridge-cloudfront-tag-change-event-routes-to-sns."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-tag-change-event-routes-to-sns"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudTrail TagResource event for a CloudFront distribution, matched by an EventBridge
    rule, is delivered to an SNS topic target (observed via an SQS subscription)."""
    # CloudFront is a global service: CloudTrail delivers its management events to EventBridge's
    # default bus ONLY in us-east-1, regardless of which region the API call is signed against or
    # which region this suite otherwise runs in. The rule, the SNS topic and the SQS queue must all
    # live in us-east-1 too — an EventBridge target ARN must be in the rule's own region.
    EVENT_REGION = "us-east-1"

    _ensure_trail(ctx, EVENT_REGION)

    caller_ref = ctx.unique_name("sim2real-cfevt-tag-")
    dist_id, dist_arn = _create_minimal_distribution(ctx, caller_ref)

    topic_arn = _create_topic(ctx, EVENT_REGION)
    queue = _create_queue(ctx, EVENT_REGION)

    pattern = {
        "source": ["aws.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["cloudfront.amazonaws.com"],
            "eventName": ["TagResource"],
        },
    }
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    events = ctx.client("events", region=EVENT_REGION)
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    _allow_eventbridge_to_publish(ctx, topic_arn, rule_arn, EVENT_REGION)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target1", "Arn": topic_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target1"]))

    sub_arn = _subscribe_queue_to_topic(ctx, topic_arn, queue, EVENT_REGION)

    tag_key = ctx.unique_name("sim2real-tag-")
    cf = ctx.client("cloudfront")
    cf.tag_resource(
        Resource=dist_arn,
        Tags={"Items": [{"Key": tag_key, "Value": "behavioral-check"}]},
    )

    def _matches(envelope: dict[str, Any]) -> bool:
        detail = envelope.get("detail", {})
        if detail.get("eventName") != "TagResource":
            return False
        req = detail.get("requestParameters", {}) or {}
        return tag_key in json.dumps(req)

    envelope = _wait_for_sns_notification(
        ctx,
        queue["url"],
        _matches,
        EVENT_REGION,
        timeout_s=900.0,
        description="TagResource CloudTrail event via SNS on SQS",
    )
    detail = envelope["detail"]
    assert detail["eventSource"] == "cloudfront.amazonaws.com", (
        f"expected eventSource cloudfront.amazonaws.com, got {detail.get('eventSource')!r}"
    )
    assert detail["eventName"] == "TagResource", (
        f"expected eventName TagResource, got {detail.get('eventName')!r}"
    )
    req = detail.get("requestParameters", {}) or {}
    assert req.get("resource") == dist_arn, (
        f"expected requestParameters.resource {dist_arn!r}, got requestParameters={req!r}"
    )
    tag_items = (req.get("tags") or {}).get("items", [])
    assert tag_items == [{"key": tag_key, "value": "behavioral-check"}], (
        f"expected tag items [{{'key': {tag_key!r}, 'value': 'behavioral-check'}}], "
        f"got {tag_items!r} (requestParameters={req!r})"
    )

    sns = ctx.client("sns", region=EVENT_REGION)
    sns.unsubscribe(SubscriptionArn=sub_arn)


# ===== helpers =====
def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _ensure_trail(ctx, region: str) -> None:
    """CloudTrail's automatic delivery of 'AWS API Call via CloudTrail' events to EventBridge's
    default bus only fires while at least one trail is actively logging management events for
    this region. A fresh account has none (describe_trails returns an empty
    trailList), so adopt an existing active trail if one already
    covers global service events, else create-and-clean-up an ephemeral one of our own."""
    ct = ctx.client("cloudtrail", region=region)
    for trail in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
        if not trail.get("IncludeGlobalServiceEvents"):
            continue
        status = ct.get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging"):
            return

    sts = ctx.client("sts")
    s3 = ctx.client("s3", region=region)
    account_id = sts.get_caller_identity()["Account"]
    bucket_name = ctx.unique_name("sim2real-cfevt-trailbucket-").lower()
    trail_name = ctx.unique_name("sim2real-cfevt-trail-")
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup_bucket() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            keys = [
                {"Key": o["Key"]}
                for page in paginator.paginate(Bucket=bucket_name)
                for o in page.get("Contents", [])
            ]
            for i in range(0, len(keys), 1000):
                s3.delete_objects(
                    Bucket=bucket_name, Delete={"Objects": keys[i : i + 1000]}
                )
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket_name,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=False,
    )

    def _cleanup_trail() -> None:
        try:
            ct.stop_logging(Name=trail_name)
            ct.delete_trail(Name=trail_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TrailNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_trail)
    ct.start_logging(Name=trail_name)
    _poll_until(
        lambda: ct.get_trail_status(Name=trail_name),
        lambda s: s.get("IsLogging") is True,
        timeout_s=60,
        interval_s=3.0,
        description=f"trail {trail_name} logging",
    )


def _create_queue(ctx, region: str) -> dict[str, str]:
    sqs = ctx.client("sqs", region=region)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cfevt-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx, region: str) -> str:
    sns = ctx.client("sns", region=region)
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-cfevt-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _allow_eventbridge_to_publish(
    ctx, topic_arn: str, rule_arn: str, region: str
) -> None:
    sns = ctx.client("sns", region=region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgePublish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
    )


def _subscribe_queue_to_topic(
    ctx, topic_arn: str, queue: dict[str, str], region: str
) -> str:
    sqs = ctx.client("sqs", region=region)
    sns = ctx.client("sns", region=region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSnsSend",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue["arn"])[
        "SubscriptionArn"
    ]
    return sub_arn


def _wait_for_sns_notification(
    ctx,
    queue_url: str,
    predicate,
    region: str,
    timeout_s: float = 600.0,
    description: str = "notification",
):
    sqs = ctx.client("sqs", region=region)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            outer = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if outer.get("Type") != "Notification":
                continue
            envelope = json.loads(outer["Message"])
            if predicate(envelope):
                return envelope
    raise AssertionError(f"{description} not observed within {timeout_s}s")


def _minimal_distribution_config(caller_reference: str) -> dict[str, Any]:
    return {
        "CallerReference": caller_reference,
        "Comment": "sim2real behavioral check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": f"{caller_reference}.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
        },
    }


def _create_minimal_distribution(ctx, caller_reference: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig=_minimal_distribution_config(caller_reference)
    )
    dist = resp["Distribution"]
    ctx.on_cleanup(lambda: _delete_distribution_safe(ctx, dist["Id"]))
    return dist["Id"], dist["ARN"]


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dist_config = cfg["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=dist_config, IfMatch=etag)
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=20.0,
        description=f"distribution {dist_id} Deployed after disable",
    )
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_distribution_safe(ctx, dist_id: str) -> None:
    try:
        _delete_distribution(ctx, dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
