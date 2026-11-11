"""crawler-metrics-reflect-run-activity."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-metrics-reflect-run-activity"
GROUP = "telemetry"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCrawlerMetrics.TablesCreated measurably increases after a crawler completes a run
    against real S3 data, compared to its baseline (never-run) value of 0."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    _put_csv_data(ctx, bucket, "crawl-data/part-0000.csv")
    role = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real_glue_db_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-glue-crawler-")

    def _create():
        glue.create_crawler(
            Name=crawler_name,
            Role=role["arn"],
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket}/crawl-data/"}]},
            Tags={"sim2real": CHECK},
        )

    _retry_on_role_not_yet_assumable(_create, timeout_s=150, interval_s=10)
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    baseline = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])["CrawlerMetricsList"][0]
    assert baseline["TablesCreated"] == 0, f"expected a never-run crawler to report TablesCreated=0, got {baseline}"

    glue.start_crawler(Name=crawler_name)

    final_crawler = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY" and "LastCrawl" in c,
        timeout_s=600,
        interval_s=15,
    )
    assert final_crawler["LastCrawl"]["Status"] == "SUCCEEDED", (
        f"expected the crawl to succeed, got LastCrawl={final_crawler.get('LastCrawl')}"
    )

    after = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])["CrawlerMetricsList"][0]
    assert after["TablesCreated"] >= 1, f"expected TablesCreated to increase, got {after}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_role_not_yet_assumable(fn, *, timeout_s=120.0, interval_s=5.0):
    # A just-created role's trust policy is not immediately visible everywhere; Glue
    # surfaces that propagation delay as either AccessDeniedException or
    # InvalidInputException("Service is unable to assume provided role"), not just one.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidInputException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-").lower().replace("_", "-")
    kwargs = {}
    # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1; this
    # is an API quirk of the call, not a region pin on the bucket itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _put_csv_data(ctx, bucket, key):
    s3 = ctx.client("s3")
    body = "\n".join(f"{i},name-{i}" for i in range(1, 51)).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return {"name": name, "arn": role_arn}


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
