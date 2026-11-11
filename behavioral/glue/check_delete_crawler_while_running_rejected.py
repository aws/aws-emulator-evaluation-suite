"""delete-crawler-while-running-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-crawler-while-running-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """DeleteCrawler while the crawler is RUNNING is rejected, and succeeds once the crawler is READY again."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alice\n2,bob\n")
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket)
    db_name = _create_database(ctx)

    crawler_name = ctx.unique_name("sim2real-glue-crd-")
    _retry_call(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=role_arn,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
            Tags={"sim2real": CHECK},
        ),
        timeout_s=180.0,
        interval_s=10.0,
    )
    deleted = {"value": False}

    def _cleanup_crawler():
        if deleted["value"]:
            return
        deadline = time.monotonic() + 600.0
        while True:
            try:
                glue.delete_crawler(Name=crawler_name)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "EntityNotFoundException":
                    return
                # A check that fails mid-crawl leaves the crawler running; wait for it to stop.
                if code != "CrawlerRunningException" or time.monotonic() >= deadline:
                    raise
            time.sleep(15)

    ctx.on_cleanup(_cleanup_crawler)

    _retry_call(lambda: glue.start_crawler(Name=crawler_name), timeout_s=180.0, interval_s=10.0)

    _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "RUNNING",
        timeout_s=60.0,
        interval_s=3.0,
    )

    code, message = _error(lambda: glue.delete_crawler(Name=crawler_name))
    assert code == "CrawlerRunningException", f"expected CrawlerRunningException, got {code}"
    expected = f"Cannot delete crawler{crawler_name} while it's running"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the crawler still exists.
    crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
    assert crawler["Name"] == crawler_name, f"expected the crawler to survive the rejected delete, got {crawler!r}"

    _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY" and "LastCrawl" in c,
        timeout_s=300.0,
        interval_s=10.0,
    )

    # Positive control: once READY again, delete succeeds.
    glue.delete_crawler(Name=crawler_name)
    deleted["value"] = True
    code, message = _error(lambda: glue.get_crawler(Name=crawler_name))
    assert code == "EntityNotFoundException", f"expected the crawler to be gone, got {code}"
    expected = f"Crawler entry with name {crawler_name} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


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
    bucket = ctx.unique_name("sim2real-glue-crd-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_database(ctx):
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_crd_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_glue_service_role(ctx, s3_bucket=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-crd-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
