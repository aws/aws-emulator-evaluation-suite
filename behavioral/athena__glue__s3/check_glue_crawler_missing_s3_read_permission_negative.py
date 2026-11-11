"""glue-crawler-missing-s3-read-permission-negative."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-crawler-missing-s3-read-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]

_GLUE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}
# Grants Glue-side permissions (Data Catalog writes, CloudWatch Logs) but only S3
# access to aws-glue-* prefixed buckets -- NOT to our own bucket.
_GLUE_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler whose role lacks s3:GetObject/ListBucket on the target bucket fails
    (LastCrawl.Status FAILED, no table published) while an identical crawler with bucket read
    access succeeds, isolating the S3 read permission as the boundary."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-crawlperm-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="data/rows.csv", Body=b"id,name\n1,alice\n2,bob\n")

    db_name = ctx.unique_name("sim2real_crawlperm_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    bad_role_arn, bad_role_name = _make_role(ctx, iam, "bad", with_bucket_read=False, bucket=bucket)
    good_role_arn, good_role_name = _make_role(ctx, iam, "good", with_bucket_read=True, bucket=bucket)

    bad_crawler = ctx.unique_name("sim2real-crawlperm-bad-")
    _create_crawler_with_retry(
        glue,
        Name=bad_crawler,
        Role=bad_role_arn,
        DatabaseName=db_name,
        TablePrefix="bad_",
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=bad_crawler))

    good_crawler = ctx.unique_name("sim2real-crawlperm-good-")
    _create_crawler_with_retry(
        glue,
        Name=good_crawler,
        Role=good_role_arn,
        DatabaseName=db_name,
        TablePrefix="good_",
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=good_crawler))

    bad_status = _run_crawler_and_wait(glue, bad_crawler, timeout_s=300, retries=0)
    good_status = _run_crawler_and_wait(glue, good_crawler, timeout_s=300, retries=2)

    # Glue crawlers can report LastCrawl.Status == SUCCEEDED even when every
    # object under the target path was inaccessible -- it silently skips what
    # it cannot list/read rather than failing the crawl outright. The real
    # behavioral boundary is therefore whether a table got published, not the
    # textual status, so assert on catalog state (with status only informative).
    assert bad_status in ("SUCCEEDED", "FAILED"), f"unexpected crawler status: {bad_status!r}"
    bad_tables = [t for t in glue.get_tables(DatabaseName=db_name)["TableList"] if t["Name"].startswith("bad_")]
    assert bad_tables == [], (
        f"crawler without S3 permission should not have published a table "
        f"(status={bad_status!r}), got {bad_tables}"
    )

    # Positive control in the same file: identical setup, only the S3 permission differs.
    assert good_status == "SUCCEEDED", f"control crawler with S3 read permission ended as {good_status!r}"
    good_tables = [t for t in glue.get_tables(DatabaseName=db_name)["TableList"] if t["Name"].startswith("good_")]
    assert len(good_tables) == 1, f"control crawler should have published exactly one table, got {good_tables}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _make_role(ctx, iam, label: str, with_bucket_read: bool, bucket: str):
    role_name = ctx.unique_name(f"sim2real-crawlperm-{label}-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_GLUE_TRUST))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY))
    if with_bucket_read:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="bucket-read", PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="bucket-read"))
    return role_arn, role_name


def _create_crawler_with_retry(glue, retries: int = 6, delay: int = 10, **kwargs) -> None:
    """A freshly created IAM role can take a short time to become assumable by
    Glue; CreateCrawler validates assumability synchronously, so retry through
    that documented eventual-consistency window instead of failing immediately."""
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as e:
            msg = str(e)
            if "unable to assume" in msg.lower() and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _run_crawler_and_wait(glue, name: str, timeout_s: int = 300, retries: int = 1) -> str | None:
    last_status = None
    for _attempt in range(retries + 1):
        glue.start_crawler(Name=name)
        deadline = time.monotonic() + timeout_s
        reached_ready = False
        while time.monotonic() < deadline:
            desc = glue.get_crawler(Name=name)["Crawler"]
            if desc["State"] == "READY":
                last_status = desc.get("LastCrawl", {}).get("Status")
                reached_ready = True
                break
            time.sleep(5)
        if not reached_ready:
            raise AssertionError(f"crawler {name} did not return to READY within {timeout_s}s")
        if last_status == "SUCCEEDED":
            return last_status
        time.sleep(2)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
