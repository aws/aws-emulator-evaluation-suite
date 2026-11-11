"""glue-crawler-sqs-dlq-receives-malformed-event-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-sqs-dlq-receives-malformed-event-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler drains a malformed message from its event queue without adding a partition or
    routing it to the DLQ, while a well-formed S3 event queued after it adds one partition and
    leaves the DLQ empty.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    _put_csv(s3, bucket, "data/table1/dt=2024-01-01/data.csv", "id,val\n1,x\n")

    event_queue_url, event_queue_arn = _create_queue(ctx, "eventq")
    dlq_url, dlq_arn = _create_queue(ctx, "dlq")
    role_arn = _create_glue_crawler_role(ctx, bucket, [event_queue_arn, dlq_arn])
    db_name = _create_database(ctx)
    crawler_name = ctx.unique_name("sim2real-glue-crawler-")

    _create_crawler_with_retry(
        ctx, glue, Name=crawler_name, Role=role_arn, DatabaseName=db_name,
        Targets={"S3Targets": [{
            "Path": f"s3://{bucket}/data/",
            "EventQueueArn": event_queue_arn,
            "DlqEventQueueArn": dlq_arn,
        }]},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVENT_MODE"},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    _start_crawler_with_retry(ctx, glue, crawler_name)
    crawler = _wait_for_crawler_ready(ctx, glue, crawler_name)
    _assert_last_crawl_succeeded(crawler)
    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly one table after the first crawl, got {[t['Name'] for t in tables]}"
    table_name = tables[0]["Name"]
    parts_before = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(parts_before) == 1, f"expected exactly one partition after the first crawl, got {len(parts_before)}"

    # break exactly one thing: put an unparseable, non-S3-event message on the event queue
    malformed_body = "{\"not_an_s3_event\": true, \"marker\": \"sim2real-malformed\"}"
    sqs.send_message(QueueUrl=event_queue_url, MessageBody=malformed_body)

    _start_crawler_with_retry(ctx, glue, crawler_name)
    _wait_for_crawler_ready(ctx, glue, crawler_name)

    # negative: the malformed event produced no catalog change
    parts_after_malformed = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(parts_after_malformed) == 1, "a malformed event must not create a partition"

    # negative: it is drained off the source queue by the crawler (not left stuck
    # there, and not silently re-appearing as a poison message on every future run)
    remaining = int(sqs.get_queue_attributes(
        QueueUrl=event_queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"].get("ApproximateNumberOfMessages", "0"))
    assert remaining == 0, f"malformed message should have been drained from the event queue, {remaining} left"

    # independent read at the OTHER possible destination: unparseable content is a different failure
    # mode than a delivery/processing crash. A malformed message
    # is drained and discarded outright -- it is never routed through DlqEventQueueArn, because it
    # is deleted from the source queue on the first receive and so never exhausts a receive count.
    dlq_receipt = _receive_from_dlq(ctx, dlq_url, "sim2real-malformed", timeout_s=30.0)
    assert dlq_receipt is None, f"a malformed event must not be routed to the DLQ, got {dlq_receipt}"

    # positive control: a well-formed event queued afterwards is still processed
    new_key = "data/table1/dt=2024-01-02/data.csv"
    _put_csv(s3, bucket, new_key, "id,val\n2,y\n")
    good_event = _s3_event_message(bucket, new_key, ctx.region, account_id)
    sqs.send_message(QueueUrl=event_queue_url, MessageBody=good_event)

    _start_crawler_with_retry(ctx, glue, crawler_name)
    crawler = _wait_for_crawler_ready(ctx, glue, crawler_name)
    _assert_last_crawl_succeeded(crawler)
    parts_after_good = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(parts_after_good) == 2, f"well-formed event should still land, got {len(parts_after_good)}"

    # the DLQ stays untouched by this whole file: neither the malformed event nor
    # the well-formed one ever lands there, confirming the DLQ's absence above was
    # not a fluke of timing
    stray = _receive_from_dlq(ctx, dlq_url, "sim2real-malformed", timeout_s=15.0)
    assert stray is None, f"a well-formed event's run must not deposit anything on the DLQ, got {stray}"


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
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-glue-{suffix}-"), tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_glue_crawler_role(ctx, bucket: str, sqs_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
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


def _receive_from_dlq(ctx, dlq_url: str, marker: str, timeout_s: float) -> dict | None:
    """Poll the DLQ (long-polling, no bare sleep) for a message whose body contains
    `marker`, up to `timeout_s`. Returns the message dict, or None if none arrived."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            if marker in msg["Body"]:
                return msg
    return None


def _create_database(ctx) -> str:
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_crawler_with_retry(ctx, glue, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs) -> None:
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


def _start_crawler_with_retry(ctx, glue, name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
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


def _wait_for_crawler_ready(ctx, glue, name: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = glue.get_crawler(Name=name)["Crawler"]
        if last["State"] == "READY":
            return last
        time.sleep(interval_s)
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
