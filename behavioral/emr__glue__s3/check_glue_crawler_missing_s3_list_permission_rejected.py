"""glue-crawler-missing-s3-list-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "glue-crawler-missing-s3-list-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler whose role cannot read the target bucket ends SUCCEEDED or FAILED with no table catalogued,
    while a sibling crawler with read access succeeds and catalogues one table: the graded boundary is
    catalog state, not the crawl status."""
    bucket = _create_bucket(ctx)
    csv_body = "id,name\n1,alpha\n2,beta\n"
    _put_object(ctx, bucket, "data/sample.csv", csv_body)

    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-glue-db-").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_database(ctx, db_name))

    # --- Negative: role has only the baseline AWSGlueServiceRole managed policy, which
    # grants no access to an arbitrary (non "aws-glue-*" prefixed) bucket. ---
    bad_role_arn = _create_glue_role(ctx, extra_statements=None)

    bad_crawler = ctx.unique_name("sim2real-glue-crawler-bad-")
    _create_crawler_with_retry(
        glue,
        Name=bad_crawler,
        Role=bad_role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=bad_crawler))
    glue.start_crawler(Name=bad_crawler)
    bad_result = _wait_for_crawler_ready(ctx, glue, bad_crawler, timeout_s=600)
    assert bad_result["LastCrawl"]["Status"] in ("SUCCEEDED", "FAILED"), bad_result.get("LastCrawl")

    code, message = _error(lambda: glue.get_table(DatabaseName=db_name, Name="sample"))
    assert code == "EntityNotFoundException", code
    assert message == "Entity Not Found", message
    assert glue.get_tables(DatabaseName=db_name)["TableList"] == []

    # --- Positive control: a role WITH s3:ListBucket/s3:GetObject succeeds in the same file. ---
    good_role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )

    good_crawler = ctx.unique_name("sim2real-glue-crawler-good-")
    _create_crawler_with_retry(
        glue,
        Name=good_crawler,
        Role=good_role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=good_crawler))
    glue.start_crawler(Name=good_crawler)
    good_result = _wait_for_crawler_ready(ctx, glue, good_crawler, timeout_s=600)
    assert good_result["LastCrawl"]["Status"] == "SUCCEEDED", good_result.get("LastCrawl")
    assert len(glue.get_tables(DatabaseName=db_name)["TableList"]) == 1


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call succeeded where an error was expected")


def _bucket_region_kwargs(ctx):
    # us-east-1 is CreateBucket's implicit default and rejects an explicit LocationConstraint
    # naming itself; every other region requires one. Not a hardcoded target region.
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _put_object(ctx, bucket: str, key: str, body) -> None:
    if isinstance(body, str):
        body = body.encode("utf-8")
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    if extra_statements:
        policy_name = ctx.unique_name("sim2real-glue-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_crawler_with_retry(glue, *, timeout_s: float = 180.0, **kwargs) -> None:
    """A freshly created IAM role can take a short time to become assumable by Glue;
    CreateCrawler validates assumability synchronously, so retry through that documented
    eventual-consistency window instead of a blind sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _delete_database(ctx, db_name: str) -> None:
    glue = ctx.client("glue")
    for table in glue.get_tables(DatabaseName=db_name).get("TableList", []):
        glue.delete_table(DatabaseName=db_name, Name=table["Name"])
    glue.delete_database(Name=db_name)


def _wait_for_crawler_ready(ctx, glue, name: str, timeout_s: float = 600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        crawler = glue.get_crawler(Name=name)["Crawler"]
        if crawler["State"] == "READY" and "LastCrawl" in crawler:
            return crawler
        time.sleep(2)
    raise AssertionError(f"crawler {name} did not finish a crawl within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
