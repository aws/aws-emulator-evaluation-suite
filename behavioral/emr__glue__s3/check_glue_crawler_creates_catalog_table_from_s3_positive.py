"""glue-crawler-creates-catalog-table-from-s3-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-crawler-creates-catalog-table-from-s3-positive"
GROUP = "resource-binding"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler scanning an S3 CSV object creates a catalog table reflecting its schema."""
    bucket = _create_bucket(ctx)
    csv_body = "id,name,amount\n1,alpha,10.5\n2,beta,20.75\n3,gamma,30.0\n"
    _put_object(ctx, bucket, "data/sample.csv", csv_body)

    role_arn = _create_glue_role(
        ctx,
        extra_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    )

    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-glue-db-").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_database(ctx, db_name))

    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    # IAM role/policy attachment can take a short time to propagate before Glue can assume the
    # role: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # CreateCrawler validates role-assumability up front and raises InvalidInputException until
    # the role is assumable, so retry it on a bounded deadline rather than guessing a fixed
    # propagation delay.
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK},
        timeout_s=120,
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    glue.start_crawler(Name=crawler_name)
    crawler = _wait_for_crawler_ready(ctx, glue, crawler_name, timeout_s=600)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler.get("LastCrawl")

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly one crawled table, got {len(tables)}"
    table = tables[0]
    columns = {c["Name"].lower() for c in table["StorageDescriptor"]["Columns"]}
    assert columns == {"id", "name", "amount"}, columns
    location = table["StorageDescriptor"]["Location"]
    expected_location = f"s3://{bucket}/data/"
    assert location == expected_location, f"expected table location {expected_location!r}, got {location!r}"


def _bucket_region_kwargs(ctx):
    if ctx.region == "us-east-1":
        return {}
    return {"CreateBucketConfiguration": {"LocationConstraint": ctx.region}}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-s3-")
    s3.create_bucket(Bucket=name, **_bucket_region_kwargs(ctx))

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


def _delete_database(ctx, db_name: str) -> None:
    glue = ctx.client("glue")
    for table in glue.get_tables(DatabaseName=db_name).get("TableList", []):
        glue.delete_table(DatabaseName=db_name, Name=table["Name"])
    glue.delete_database(Name=db_name)


def _create_crawler_with_retry(glue, *, timeout_s: float = 120.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"crawler {kwargs.get('Name')} could not be created within {timeout_s}s: {last_exc}")


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
