"""glue-crawler-sqs-visibility-timeout-redrive-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-sqs-visibility-timeout-redrive-positive"
GROUP = "delivery"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler stores its EventQueueArn and DlqEventQueueArn, and an event message received but
    never deleted past maxReceiveCount moves to the DLQ, leaving the source queue empty.
    """
    sqs = ctx.client("sqs")

    dlq_url, dlq_arn = _create_queue(ctx, "dlq")
    event_queue_url, event_queue_arn = _create_queue(ctx, "eventq")

    redrive_policy = {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}
    sqs.set_queue_attributes(
        QueueUrl=event_queue_url,
        Attributes={
            "RedrivePolicy": json.dumps(redrive_policy),
            "VisibilityTimeout": "1",
        },
    )

    # Tie the queue pair to an actual (never-started) crawler config, matching how
    # this redrive contract is meant to be consumed in practice.
    role_arn = _create_glue_role(ctx, [event_queue_arn, dlq_arn])
    db_name = _create_database(ctx)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="data/seed.csv", Body=b"id,val\n1,a\n")
    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    glue = ctx.client("glue")

    # IAM role trust/attachment is eventually consistent — Glue's assume-role
    # check on CreateCrawler can fail for a few seconds right after the role
    # was created, so retry past that propagation window.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            glue.create_crawler(
                Name=crawler_name,
                Role=role_arn,
                DatabaseName=db_name,
                Targets={"S3Targets": [{
                    "Path": f"s3://{bucket}/data/",
                    "EventQueueArn": event_queue_arn,
                    "DlqEventQueueArn": dlq_arn,
                }]},
                RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVENT_MODE"},
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if "unable to assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: ctx.client("glue").delete_crawler(Name=crawler_name))

    # independent read at the destination: confirm Glue itself accepted and persisted the
    # queue pairing, not just that CreateCrawler returned without raising
    persisted_target = glue.get_crawler(Name=crawler_name)["Crawler"]["Targets"]["S3Targets"][0]
    assert persisted_target["EventQueueArn"] == event_queue_arn, (
        f"expected EventQueueArn {event_queue_arn}, got {persisted_target.get('EventQueueArn')}"
    )
    assert persisted_target["DlqEventQueueArn"] == dlq_arn, (
        f"expected DlqEventQueueArn {dlq_arn}, got {persisted_target.get('DlqEventQueueArn')}"
    )

    marker = "sim2real-redrive-marker"
    sqs.send_message(QueueUrl=event_queue_url, MessageBody=marker)

    _drain_without_deleting_until_redriven(ctx, event_queue_url, dlq_url, marker, timeout_s=60.0)

    # invariant: the source queue no longer holds the message once it was redriven
    remaining = int(sqs.get_queue_attributes(
        QueueUrl=event_queue_url, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    )["Attributes"].get("ApproximateNumberOfMessages", "0"))
    assert remaining == 0, f"source queue should be empty after redrive, has {remaining}"


def _create_queue(ctx, suffix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-glue-redrive-{suffix}-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-redrive-")
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


def _create_glue_role(ctx, sqs_queue_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-redrive-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    inline_policy_name = "sim2real-glue-redrive-sqs-access"

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")

    # Glue's event-mode crawler requires the crawler role to be explicitly
    # granted these SQS actions on both the event queue and the DLQ (the
    # managed AWSGlueServiceRole policy does not include them) —
    # https://docs.aws.amazon.com/glue/latest/dg/crawler-s3-event-notifications.html
    sqs_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "GlueEventQueueAccess",
            "Effect": "Allow",
            "Action": [
                "sqs:DeleteMessage",
                "sqs:GetQueueUrl",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:ReceiveMessage",
                "sqs:GetQueueAttributes",
                "sqs:ListQueueTags",
                "sqs:SetQueueAttributes",
                "sqs:PurgeQueue",
                "sqs:SendMessage",
            ],
            "Resource": sqs_queue_arns,
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(sqs_policy))
    return role["Arn"]


def _create_database(ctx) -> str:
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_redrive_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _drain_without_deleting_until_redriven(ctx, source_url: str, dlq_url: str, marker: str, timeout_s: float) -> None:
    """Repeatedly receive-without-delete from source (simulating a consumer that
    always fails to process the message) while polling the DLQ, until the message
    shows up on the DLQ (the observable condition being polled for)."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sqs.receive_message(QueueUrl=source_url, MaxNumberOfMessages=1, WaitTimeSeconds=1, VisibilityTimeout=1)
        dlq_resp = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        messages = dlq_resp.get("Messages", [])
        if messages and messages[0]["Body"] == marker:
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=messages[0]["ReceiptHandle"])
            return
        time.sleep(1.5)
    raise AssertionError(f"message was never redriven to the DLQ within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
