"""e2e-crawler-populates-catalog-then-teardown."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-crawler-populates-catalog-then-teardown"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3-target crawler run to completion adds a table pointing at the crawled prefix to
    GetTables, and DeleteCrawler/DeleteDatabase leave both names answering EntityNotFoundException.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-crawl-").lower().rstrip("-")
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    key = "data/sample.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=b"id,name\n1,alice\n2,bob\n")

    role_name = ctx.unique_name("sim2real-behav-crawler-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "glue.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        )
    )

    inline_policy_name = "sim2real-behav-s3-access"
    inline_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
                {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=inline_policy)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        )
    )

    db_name = ctx.unique_name("sim2real_behav_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_database(Name=db_name)))

    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_crawler(Name=crawler_name)))

    last_crawl = None
    for attempt in range(2):
        glue.start_crawler(Name=crawler_name)
        last_crawl = _wait_for_crawler_ready(glue, crawler_name, timeout_s=300, interval_s=2)
        if last_crawl.get("Status") == "SUCCEEDED":
            break
        time.sleep(2)  # retry once more in case of IAM propagation lag
    assert last_crawl is not None and last_crawl.get("Status") == "SUCCEEDED", (
        f"crawler did not succeed after retries: {last_crawl}"
    )

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "expected crawler to create at least one table"
    assert any(bucket in t.get("StorageDescriptor", {}).get("Location", "") for t in tables), (
        "expected a crawled table to point at our S3 bucket"
    )

    # Explicit teardown of the checked resources, verified rather than fire-and-forget.
    glue.delete_crawler(Name=crawler_name)
    crawler_gone = _error_code(lambda: glue.get_crawler(Name=crawler_name))
    assert crawler_gone == ("EntityNotFoundException", f"Crawler entry with name {crawler_name} does not exist"), crawler_gone

    glue.delete_database(Name=db_name)
    database_gone = _error_code(lambda: glue.get_database(Name=db_name))
    assert database_gone == ("EntityNotFoundException", f"Database {db_name} not found."), database_gone


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is a literal here only because CreateBucket rejects an explicit
    # LocationConstraint for that region; the branch still follows ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_crawler_with_retry(glue, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs) -> None:
    """CreateCrawler validates that the service can assume the given role synchronously,
    so it can fail with InvalidInputException while IAM role/policy propagation is
    still in flight right after the role was created; retry until that clears.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "NoSuchEntity"):
            raise


def _wait_for_crawler_ready(glue, crawler_name: str, timeout_s: float, interval_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
        state = crawler.get("State")
        if state == "READY":
            return crawler.get("LastCrawl", {})
        time.sleep(interval_s)
    raise AssertionError(f"crawler did not return to READY within {timeout_s}s (last state={state})")


def _error_code(fn: Callable[[], Any]) -> tuple:
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
