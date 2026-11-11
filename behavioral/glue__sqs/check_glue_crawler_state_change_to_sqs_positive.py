"""glue-crawler-state-change-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-state-change-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real Glue crawler that completes SUCCESSFULLY emits a "Glue Crawler State
    Change" event with state Succeeded, delivered to SQS via an EventBridge rule."""
    bucket = _create_crawl_bucket(ctx)
    role_arn = _create_glue_crawler_role(ctx, bucket)
    db_name = _create_database(ctx)
    crawler_name = _create_crawler(ctx, role_arn, db_name, bucket)

    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["aws.glue"],
            "detail-type": ["Glue Crawler State Change"],
            "detail": {"crawlerName": [crawler_name], "state": ["Succeeded"]},
        },
    )
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, queue_url, queue_arn, rule_arn)
    _put_sqs_target(ctx, rule_name, queue_arn)

    glue = ctx.client("glue")
    glue.start_crawler(Name=crawler_name)

    body = _drain_queue_until_match(
        ctx,
        queue_url,
        lambda b: isinstance(b, dict)
        and b.get("detail", {}).get("crawlerName") == crawler_name,
        timeout_s=480.0,
    )
    assert body["source"] == "aws.glue", f"expected source 'aws.glue', got {body['source']!r}"
    assert body["detail-type"] == "Glue Crawler State Change", (
        f"expected detail-type 'Glue Crawler State Change', got {body['detail-type']!r}"
    )
    assert body["detail"]["state"] == "Succeeded", (
        f"expected detail.state 'Succeeded', got {body['detail'].get('state')!r}"
    )

    # GetCrawler's own LastCrawl field is eventually consistent relative to the state-change
    # event: an immediate read here can still show no LastCrawl at all (observed on real AWS).
    crawler = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c.get("LastCrawl", {}).get("Status") == "SUCCEEDED",
        timeout_s=60.0,
        interval_s=3.0,
        description="GetCrawler LastCrawl to report SUCCEEDED",
    )
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", (
        f"expected LastCrawl.Status 'SUCCEEDED', got {crawler.get('LastCrawl')}"
    )


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


def _create_crawl_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-crawl-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(
        Bucket=bucket,
        Key="data/sample.csv",
        Body=b"id,name\n1,alice\n2,bob\n",
    )
    return bucket


def _create_glue_crawler_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-crole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    )

    inline_name = "sim2real-glue-crawl-s3-access"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
    )
    return role["Arn"]


def _create_database(ctx) -> str:
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    return db_name


def _create_crawler(ctx, role_arn: str, db_name: str, bucket: str) -> str:
    glue = ctx.client("glue")
    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))
    return crawler_name


def _create_crawler_with_retry(glue, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs) -> None:
    # A freshly-created IAM role can take a few seconds to propagate; Glue validates the
    # role at CreateCrawler time and rejects it until propagation completes.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidInputException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-rule-")
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _set_queue_policy_for_rule(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _put_sqs_target(ctx, rule_name: str, queue_arn: str) -> None:
    events = ctx.client("events")
    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _drain_queue_until_match(ctx, queue_url: str, predicate, timeout_s=300.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {"msg": None}

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found["msg"] is None and predicate(body):
                found["msg"] = body
        return found["msg"]

    _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="matching SQS message",
    )
    return found["msg"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
