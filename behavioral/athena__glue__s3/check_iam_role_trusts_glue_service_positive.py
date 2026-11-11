"""iam-role-trusts-glue-service-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "iam-role-trusts-glue-service-positive"
GROUP = "iam-trust"
SERVICES = ["athena", "glue", "s3"]

_GLUE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_GLUE_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting glue.amazonaws.com is actually assumable by Glue: a crawler using it starts,
    runs to completion and writes a table into the Data Catalog, which needs sts:AssumeRole."""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    bucket = ctx.unique_name("sim2real-gluetrust-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="data/rows.csv", Body=b"id,name\n1,alice\n2,bob\n3,carol\n")

    role_name = ctx.unique_name("sim2real-gluetrust-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_GLUE_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_GLUE_MANAGED_POLICY))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="bucket-read", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="bucket-read"))

    db_name = _glue_db_name(ctx, "gluetrust")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-gluetrust-crawler-")
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    status = _run_crawler_and_wait(glue, crawler_name, timeout_s=300, retries=2)
    assert status == "SUCCEEDED", f"crawler LastCrawl.Status={status!r} -- role was not usable by Glue"

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "role was assumable but crawler produced no catalog table"
    columns = {c["Name"] for c in tables[0]["StorageDescriptor"]["Columns"]}
    assert {"id", "name"} <= columns, (
        f"catalog table columns={columns!r} -- crawler did not correctly infer the CSV header "
        "it could only have read by successfully assuming this role"
    )


def _create_bucket(ctx, s3, name: str) -> None:
    # us-east-1 is the one region S3's CreateBucket rejects a LocationConstraint for -- the
    # literal names that API quirk, not an assumption about which region this check runs in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _glue_db_name(ctx, prefix: str) -> str:
    return ctx.unique_name(f"sim2real_{prefix}_db_").replace("-", "_").lower()


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
        # A freshly created/updated IAM role can take a short time to become usable
        # for AssumeRole by other AWS services (documented eventual consistency):
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
        time.sleep(2)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
