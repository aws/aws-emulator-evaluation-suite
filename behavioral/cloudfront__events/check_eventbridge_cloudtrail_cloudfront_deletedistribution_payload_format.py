"""eventbridge-cloudtrail-cloudfront-deletedistribution-payload-format."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-cloudtrail-cloudfront-deletedistribution-payload-format"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteDistribution (GetDistributionConfig then answers NoSuchDistribution with its exact message), the
    CloudTrail DeleteDistribution event reaches SQS through EventBridge with eventSource, eventName and the
    distribution Id intact and no detail 'resources' entry, as for every CloudFront management event."""
    # CloudFront is a global service, and AWS docs state plainly that CloudTrail records its
    # events in us-east-1 regardless of the caller's region -- so the default event bus that
    # receives them also lives in us-east-1; a rule on any other region's default bus never
    # sees this event. https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/logging_using_cloudtrail.html
    #
    # EventBridge receives "AWS API Call via CloudTrail" events only while the account has an
    # active trail logging management events, and an account has none by default, so the check
    # provisions its own.
    # https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html#cloudtrail-aws-service-specific-topics-eventbridge
    _ensure_cloudtrail_trail(ctx)
    queue = _create_queue(ctx)
    pattern = {
        "source": ["aws.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"eventSource": ["cloudfront.amazonaws.com"], "eventName": ["DeleteDistribution"]},
    }
    rule_name, rule_arn = _create_rule(ctx, pattern)
    _allow_eventbridge_to_sqs(ctx, queue["url"], queue["arn"], rule_arn)
    events = ctx.client("events", region="us-east-1")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target1"]))

    caller_ref = ctx.unique_name("sim2real-cfevt-deldist-")
    dist_id = _create_minimal_distribution(ctx, caller_ref)
    _delete_distribution(ctx, dist_id)  # the action under test: fires the DeleteDistribution event

    cf = ctx.client("cloudfront")
    try:
        cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution as exc:
        message = exc.response["Error"].get("Message")
        assert message == "The specified distribution does not exist.", (
            f"GetDistributionConfig NoSuchDistribution message: {message!r}"
        )
    else:
        raise AssertionError(
            f"get_distribution_config succeeded for {dist_id} after DeleteDistribution -- "
            "the same call that read its config while it existed must now report it gone"
        )

    def _matches(body: dict[str, Any]) -> bool:
        detail = body.get("detail", {})
        return (
            detail.get("eventName") == "DeleteDistribution"
            and detail.get("requestParameters", {}).get("id") == dist_id
        )

    envelope = _wait_for_queue_message(
        ctx, queue["url"], _matches, timeout_s=1500.0, description="DeleteDistribution CloudTrail event on SQS"
    )
    detail = envelope["detail"]
    assert detail["eventSource"] == "cloudfront.amazonaws.com"
    assert detail["eventName"] == "DeleteDistribution"
    assert detail["requestParameters"]["id"] == dist_id
    resources = detail.get("resources", [])
    assert resources == [], (
        "CloudFront management events carry no 'resources' field identifying the "
        f"distribution (unlike its KeyValueStore data events) -- got {resources!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ensure_cloudtrail_trail(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ct = ctx.client("cloudtrail", region="us-east-1")
    s3 = ctx.client("s3", region="us-east-1")

    bucket_name = ctx.unique_name("sim2real-cfevt-trail-")
    s3.create_bucket(Bucket=bucket_name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))

    trail_name = ctx.unique_name("sim2real-cfevt-trail-")
    trail_arn = f"arn:aws:cloudtrail:us-east-1:{account_id}:trail/{trail_name}"
    bucket_policy = {
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
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    ct.create_trail(
        Name=trail_name,
        S3BucketName=bucket_name,
        IncludeGlobalServiceEvents=True,
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False,
    )
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    ct.start_logging(Name=trail_name)
    ctx.on_cleanup(lambda: ct.stop_logging(Name=trail_name))

    _poll_until(
        lambda: ct.get_trail_status(Name=trail_name)["IsLogging"],
        lambda logging: logging is True,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"trail {trail_name} actively logging",
    )
    return trail_name


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3", region="us-east-1")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = page.get("Contents", [])
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_queue(ctx) -> dict[str, str]:
    # us-east-1: this queue must sit on the same region's default event bus that carries
    # CloudFront's (global-service) CloudTrail events -- see the note in run().
    sqs = ctx.client("sqs", region="us-east-1")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cfevt-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _wait_for_queue_message(ctx, queue_url, predicate, timeout_s=600.0, description="message"):
    sqs = ctx.client("sqs", region="us-east-1")
    deadline = time.monotonic() + timeout_s
    seen: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (ValueError, TypeError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                return body
            if len(seen) < 5:
                seen.append(body)
    raise AssertionError(
        f"{description} not observed within {timeout_s}s; {len(seen)} non-matching message(s) seen: {seen!r}"
    )


def _create_rule(ctx, event_pattern: dict) -> tuple[str, str]:
    events = ctx.client("events", region="us-east-1")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, rule_arn


def _allow_eventbridge_to_sqs(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs", region="us-east-1")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


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


def _create_minimal_distribution(ctx, caller_reference: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(DistributionConfig=_minimal_distribution_config(caller_reference))
    dist = resp["Distribution"]
    ctx.on_cleanup(lambda: _delete_distribution_safe(ctx, dist["Id"]))
    return dist["Id"]


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dist_config = cfg["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=dist_config, IfMatch=etag)
    # AWS docs: a distribution must reach status "Deployed" after being disabled before it can
    # be deleted -- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HowToDeleteDistribution.html
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
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
