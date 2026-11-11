"""sdk-glue-crawler-completion-sends-sqs-message-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sdk-glue-crawler-completion-sends-sqs-message-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]

GLUE_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"

_CSV_BODY = "id,value\n1,a\n2,b\n"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Polling get_crawler for completion (State back to READY, LastCrawl SUCCEEDED, catalog
    table actually created) drives a post-processing push of the crawl result to SQS.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_glue_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=_CSV_BODY.encode("utf-8"))

    _, role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real_glue_db_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-crawler-")
    _retry_role_propagation(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=role_arn,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
            Tags={"sim2real-check": CHECK},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    _retry_role_propagation(lambda: glue.start_crawler(Name=crawler_name))

    last_crawl = _poll_crawler_completion(ctx, crawler_name, timeout_s=900.0, interval_s=15.0)
    assert last_crawl["Status"] == "SUCCEEDED", last_crawl

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "crawler did not populate the Data Catalog"
    table_name = tables[0]["Name"]
    columns = {c["Name"] for c in tables[0]["StorageDescriptor"]["Columns"]}
    assert {"id", "value"}.issubset(columns), f"catalog schema {columns} does not match the crawled CSV header"

    queue_url, _ = _create_queue(ctx)
    sqs = ctx.client("sqs")
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(
            {"crawler": crawler_name, "database": db_name, "table": table_name, "status": "SUCCEEDED"}
        ),
    )
    body = _receive_one_json_body(ctx, queue_url, timeout_s=60.0)
    assert body["crawler"] == crawler_name
    assert body["database"] == db_name
    assert body["table"] == table_name
    assert body["status"] == "SUCCEEDED"


def _retry_role_propagation(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Retry a call that needs Glue to assume a just-created IAM role: attach-to-usable
    propagation is eventually consistent, so a fresh role reads AccessDenied/InvalidInput
    ("Service is unable to assume provided role") for a window after creation."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _poll_crawler_completion(ctx, crawler_name: str, timeout_s: float, interval_s: float) -> dict:
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    resp: dict = {}
    while time.monotonic() < deadline:
        resp = glue.get_crawler(Name=crawler_name)["Crawler"]
        if resp.get("State") == "READY" and "LastCrawl" in resp:
            return resp["LastCrawl"]
        time.sleep(interval_s)
    raise AssertionError(f"crawler did not complete within {timeout_s}s: {resp}")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-sqs-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_glue_role(ctx, inline_statements=None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=GLUE_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=GLUE_MANAGED_POLICY_ARN))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-glue-inline-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_glue_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("aws-glue-sim2real-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _receive_one_json_body(ctx, queue_url: str, timeout_s: float) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return json.loads(msg["Body"])
    raise AssertionError(f"no message within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
