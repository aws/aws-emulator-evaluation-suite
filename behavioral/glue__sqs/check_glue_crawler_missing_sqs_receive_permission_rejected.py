"""glue-crawler-missing-sqs-receive-permission-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-missing-sqs-receive-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateCrawler rejects an EventQueueArn the role cannot read with InvalidInputException.

    No crawler is created; the same crawler with the SQS grant is created and crawls an S3 event.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    _put_csv(s3, bucket, "bad/table1/dt=2024-01-01/data.csv", "id,val\n1,x\n")
    _put_csv(s3, bucket, "good/table1/dt=2024-01-01/data.csv", "id,val\n1,x\n")

    bad_queue_url, bad_queue_arn = _create_queue(ctx, "badq")
    good_queue_url, good_queue_arn = _create_queue(ctx, "goodq")

    bad_role_arn = _create_glue_crawler_role(ctx, bucket, sqs_arns=None)
    good_role_arn = _create_glue_crawler_role(ctx, bucket, sqs_arns=[good_queue_arn])

    bad_db = _create_database(ctx)
    good_db = _create_database(ctx)
    bad_crawler = ctx.unique_name("sim2real-glue-bad-crawler-")
    good_crawler = ctx.unique_name("sim2real-glue-good-crawler-")

    # Glue validates the role's SQS access at CreateCrawler time, not lazily at crawl time.
    create_error, create_message = _create_crawler_expect_error(
        ctx, glue, Name=bad_crawler, Role=bad_role_arn, DatabaseName=bad_db,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/bad/", "EventQueueArn": bad_queue_arn}]},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVENT_MODE"},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
    )
    assert create_error == "InvalidInputException", f"expected InvalidInputException, got {create_error!r}"
    expected_message = (
        f"SQS queue {bad_queue_arn} does not exist or the role provided does not have access to it."
    )
    assert create_message == expected_message, f"expected message {expected_message!r}, got {create_message!r}"
    listed = glue.get_crawlers()["Crawlers"]
    assert bad_crawler not in {c["Name"] for c in listed}, "crawler must not exist after a rejected CreateCrawler"

    # Positive control: the same pairing WITH the SQS grant is created and crawls.
    _create_crawler_with_retry(
        ctx, glue, Name=good_crawler, Role=good_role_arn, DatabaseName=good_db,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/good/", "EventQueueArn": good_queue_arn}]},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVENT_MODE"},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=good_crawler))

    first_prev = _last_crawl_start(glue, good_crawler)
    _start_crawler_with_retry(ctx, glue, good_crawler)
    crawler = _wait_for_crawler_ready(ctx, glue, good_crawler, first_prev)
    _assert_last_crawl_succeeded(crawler)

    good_tables = glue.get_tables(DatabaseName=good_db)["TableList"]
    assert len(good_tables) == 1, f"expected exactly one table after the first crawl, got {[t['Name'] for t in good_tables]}"
    table_name = good_tables[0]["Name"]

    parts_good_before = glue.get_partitions(DatabaseName=good_db, TableName=table_name)["Partitions"]
    assert len(parts_good_before) == 1, f"expected exactly one partition after the first crawl, got {len(parts_good_before)}"

    _put_csv(s3, bucket, "good/table1/dt=2024-01-02/data.csv", "id,val\n2,y\n")
    good_event = _s3_event_message(bucket, "good/table1/dt=2024-01-02/data.csv", ctx.region, account_id)
    sqs.send_message(QueueUrl=good_queue_url, MessageBody=good_event)

    second_prev = _last_crawl_start(glue, good_crawler)
    _start_crawler_with_retry(ctx, glue, good_crawler)
    good_result = _wait_for_crawler_ready(ctx, glue, good_crawler, second_prev)

    assert good_result["LastCrawl"]["Status"] == "SUCCEEDED", good_result["LastCrawl"]
    parts_good_after = glue.get_partitions(DatabaseName=good_db, TableName=table_name)["Partitions"]
    assert len(parts_good_after) == 2, f"expected the new partition to land, got {len(parts_good_after)}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-sqs-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _put_csv(s3, bucket: str, key: str, body: str) -> None:
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))


def _create_queue(ctx, suffix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-glue-{suffix}-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_glue_crawler_role(ctx, bucket: str, sqs_arns: list[str] | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy))
    if sqs_arns:
        sqs_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueUrl",
                    "sqs:GetQueueAttributes", "sqs:ListQueueTags", "sqs:SendMessage",
                    "sqs:PurgeQueue", "sqs:ListDeadLetterSourceQueues", "sqs:SetQueueAttributes",
                ],
                "Resource": sqs_arns,
            }],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="sqs-access", PolicyDocument=json.dumps(sqs_policy))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for pol in ("s3-access", "sqs-access"):
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_database(ctx) -> str:
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_crawler_with_retry(ctx, glue, timeout_s: float = 90.0, interval_s: float = 2.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code in ("InvalidInputException", "AccessDeniedException") and "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_crawler_expect_error(ctx, glue, timeout_s: float = 90.0, interval_s: float = 2.0, **kwargs) -> tuple[str, str]:
    """Expect CreateCrawler to be rejected; retry only past assume-role propagation.

    Returns the (code, message) surfaced instead of raising.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            raise AssertionError("expected CreateCrawler to be rejected, but it succeeded")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code in ("InvalidInputException", "AccessDeniedException") and "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, msg


def _start_crawler_with_retry(ctx, glue, name: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.start_crawler(Name=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidInputException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _last_crawl_start(glue, name: str):
    return glue.get_crawler(Name=name)["Crawler"].get("LastCrawl", {}).get("StartTime")


def _wait_for_crawler_ready(ctx, glue, name: str, prev_start, timeout_s: float = 600.0, interval_s: float = 1.0) -> dict:
    """Wait until the crawler is READY with a LastCrawl newer than prev_start."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = glue.get_crawler(Name=name)["Crawler"]
        new_crawl = last.get("LastCrawl", {}).get("StartTime")
        if last["State"] == "READY" and new_crawl is not None and new_crawl != prev_start:
            return last
        if time.monotonic() + interval_s >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"crawler {name} reaching READY with a new LastCrawl: the run budget ended first; not graded")
    raise AssertionError(f"crawler {name} never reached READY within {timeout_s}s (last={last})")


def _assert_last_crawl_succeeded(crawler: dict) -> None:
    lc = crawler.get("LastCrawl", {})
    assert lc.get("Status") == "SUCCEEDED", f"LastCrawl status={lc.get('Status')} error={lc.get('ErrorMessage')}"


def _s3_event_message(bucket: str, key: str, region: str, account_id: str, event_name: str = "ObjectCreated:Put") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return json.dumps({
        "Records": [{
            "eventVersion": "2.1",
            "eventSource": "aws:s3",
            "awsRegion": region,
            "eventTime": now,
            "eventName": event_name,
            "userIdentity": {"principalId": "AWS:EXAMPLE"},
            "requestParameters": {"sourceIPAddress": "127.0.0.1"},
            "responseElements": {"x-amz-request-id": "EXAMPLE123", "x-amz-id-2": "EXAMPLE123/abc"},
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": "sim2real-event",
                "bucket": {
                    "name": bucket,
                    "ownerIdentity": {"principalId": f"AWS:{account_id}"},
                    "arn": f"arn:aws:s3:::{bucket}",
                },
                "object": {
                    "key": key,
                    "size": 100,
                    "eTag": "d41d8cd98f00b204e9800998ecf8427e",
                    "sequencer": "0055AED6DCD90281E5",
                },
            },
        }]
    })


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
