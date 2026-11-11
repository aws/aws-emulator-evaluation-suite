"""delete-nonexistent-crawler-fails."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-crawler-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a real crawler is deleted once, DeleteCrawler and GetCrawler on its name raise
    EntityNotFoundException ("Crawler entry with name <name> does not exist").
    """
    glue = ctx.client("glue")
    db_name = _create_database(ctx)
    bucket_name = _create_bucket(ctx)
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket_name)
    name = ctx.unique_name("sim2real-behav-crawler-missing-")

    _retry_call(
        lambda: glue.create_crawler(
            Name=name,
            Role=role_arn,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket_name}/data/"}]},
            Tags={"sim2real": CHECK},
        ),
        timeout_s=180.0,
        interval_s=10.0,
    )
    deleted = {"value": False}

    def _cleanup_crawler() -> None:
        if not deleted["value"]:
            try:
                glue.delete_crawler(Name=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_crawler)

    # Positive control: deleting the real, existing crawler succeeds.
    glue.delete_crawler(Name=name)
    deleted["value"] = True

    # Negative: deleting the identical (now guaranteed nonexistent) name fails specifically,
    # not silently.
    code = _refusal(lambda: glue.delete_crawler(Name=name))
    assert code == ("EntityNotFoundException", f"Crawler entry with name {name} does not exist"), (
        f"expected EntityNotFoundException deleting an unknown crawler, got {code}"
    )

    # Effect absent: an independent read (GetCrawler, not DeleteCrawler) confirms the crawler
    # is truly gone, not resurrected by the failed delete.
    get_code = _refusal(lambda: glue.get_crawler(Name=name))
    assert get_code == ("EntityNotFoundException", f"Crawler entry with name {name} does not exist"), (
        f"expected the deleted crawler to be gone, got {get_code}"
    )


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-dncf-").replace("_", "-").lower()
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically;
    # this is the API's own quirk, not a region pin on the check.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alice\n2,bob\n")

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_database(ctx) -> str:
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_dncf_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_glue_service_role(ctx, *, s3_bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-dncf-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
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
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{s3_bucket}", f"arn:aws:s3:::{s3_bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
