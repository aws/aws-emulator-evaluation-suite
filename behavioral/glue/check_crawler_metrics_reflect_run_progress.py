"""crawler-metrics-reflect-run-progress."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "crawler-metrics-reflect-run-progress"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCrawlerMetrics reflects real crawl progress: zero TablesCreated before
    the crawler ever runs, a live entry while it is RUNNING, and TablesCreated
    incremented once the run SUCCEEDED (not a static/placeholder snapshot)."""
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key="data/sample.csv",
        Body=b"id,name\n1,alpha\n2,beta\n3,gamma\n",
        ContentType="text/csv",
    )

    role_arn = _create_crawler_role(ctx, bucket)

    db_name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    glue.create_database(
        DatabaseInput={"Name": db_name}, Tags={"simparity-check": CHECK}
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-crawler-")
    _create_crawler_with_retry(
        glue, crawler_name, role_arn, db_name, f"s3://{bucket}/data/"
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    # Baseline: the crawler has never run, so it has created zero tables and is
    # not estimating anything yet.
    baseline = _get_metrics(glue, crawler_name)
    assert baseline is not None, "GetCrawlerMetrics returned no entry for a freshly created crawler"
    assert baseline["TablesCreated"] == 0
    assert baseline["StillEstimating"] is False

    glue.start_crawler(Name=crawler_name)

    saw_running_metrics = False
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        state = glue.get_crawler(Name=crawler_name)["Crawler"]["State"]
        metrics = _get_metrics(glue, crawler_name)
        if state == "RUNNING" and metrics is not None:
            saw_running_metrics = True
            assert isinstance(metrics["TimeLeftSeconds"], float)
        if state == "READY":
            break
        time.sleep(3)
    else:
        raise AssertionError("crawler did not return to READY within 360s")

    assert saw_running_metrics, (
        "GetCrawlerMetrics never returned a live entry for the crawler while it "
        "was RUNNING"
    )

    final_crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
    assert final_crawler["LastCrawl"]["Status"] == "SUCCEEDED"

    final_metrics = _get_metrics(glue, crawler_name)
    assert final_metrics is not None
    assert final_metrics["TablesCreated"] >= 1, (
        f"expected TablesCreated to reflect the completed crawl, got {final_metrics}"
    )
    assert final_metrics["TablesCreated"] > baseline["TablesCreated"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-crawl-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_crawler_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-crawl-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["Role"]["Arn"]

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    inline_policy_name = "sim2real-glue-crawl-s3-access"
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(s3_policy),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_crawler_with_retry(
    glue, crawler_name: str, role_arn: str, db_name: str, s3_path: str
) -> None:
    # New IAM roles/policies are not always immediately assumable across the AWS
    # control plane; retry on the specific errors that mean "role not yet
    # propagated" rather than sleeping blindly before the first attempt.
    deadline = time.monotonic() + 120
    while True:
        try:
            glue.create_crawler(
                Name=crawler_name,
                Role=role_arn,
                DatabaseName=db_name,
                Targets={"S3Targets": [{"Path": s3_path}]},
                Tags={"simparity-check": CHECK},
            )
            return
        except glue.exceptions.InvalidInputException:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
        except ClientError as e:
            if e.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _get_metrics(glue, crawler_name: str):
    resp = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])
    for metrics in resp.get("CrawlerMetricsList", []):
        if metrics.get("CrawlerName") == crawler_name:
            return metrics
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
