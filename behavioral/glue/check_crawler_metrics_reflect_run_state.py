"""crawler-metrics-reflect-run-state."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-metrics-reflect-run-state"
GROUP = "telemetry"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """GetCrawlerMetrics values change measurably before vs after a crawl run (live telemetry, not a static placeholder)."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alice\n2,bob\n")
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket)

    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    db_name = _create_database(ctx)
    _retry_call(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=role_arn,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
            Tags={"sim2real:managed": "true"},
        ),
        timeout_s=180.0,
        interval_s=10.0,
    )

    def _cleanup_crawler():
        try:
            glue.delete_crawler(Name=crawler_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_crawler)

    metrics_before = _get_metrics(glue, crawler_name)
    assert metrics_before["LastRuntimeSeconds"] == 0.0, (
        f"expected LastRuntimeSeconds=0 before any crawl, got: {metrics_before}"
    )

    _retry_call(lambda: glue.start_crawler(Name=crawler_name), timeout_s=180.0, interval_s=10.0)

    _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY" and "LastCrawl" in c,
        timeout_s=300.0,
        interval_s=10.0,
    )

    metrics_after = _get_metrics(glue, crawler_name)
    assert metrics_after["LastRuntimeSeconds"] > 0.0, (
        f"expected LastRuntimeSeconds > 0 after a completed crawl, got: {metrics_after}"
    )

    glue.delete_crawler(Name=crawler_name)
    try:
        glue.get_crawler(Name=crawler_name)
        raise AssertionError(f"expected {crawler_name} to be gone after delete_crawler, but get_crawler still found it")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException reading a deleted crawler {crawler_name}, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"Crawler entry with name {crawler_name} does not exist", (
            f"unexpected GetCrawler message: {message!r}"
        )
    try:
        glue.start_crawler(Name=crawler_name)
        raise AssertionError(f"expected start_crawler on deleted crawler {crawler_name} to fail")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException starting a deleted crawler {crawler_name}, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"Crawler with name {crawler_name} does not exist", (
            f"unexpected StartCrawler message: {message!r}"
        )


def _get_metrics(glue, crawler_name):
    resp = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])
    metrics = [m for m in resp["CrawlerMetricsList"] if m["CrawlerName"] == crawler_name]
    assert len(metrics) == 1, f"expected exactly one metrics entry for {crawler_name}, got {metrics}"
    return metrics[0]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-crm-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_database(ctx):
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_crm_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name}, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_glue_service_role(ctx, s3_bucket=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-crm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    if s3_bucket:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{s3_bucket}", f"arn:aws:s3:::{s3_bucket}/*"],
            }],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
