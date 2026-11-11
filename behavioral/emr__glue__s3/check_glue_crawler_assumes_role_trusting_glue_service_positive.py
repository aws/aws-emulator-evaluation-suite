"""glue-crawler-assumes-role-trusting-glue-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "glue-crawler-assumes-role-trusting-glue-service-positive"
GROUP = "iam-trust"
SERVICES = ["emr", "glue", "s3"]

_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
_CRAWLER_TERMINAL_STATE = "READY"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue crawler whose IAM role trusts glue.amazonaws.com successfully assumes that role to
    read S3, and the crawl actually populates the Data Catalog with a table -- not merely a
    crawler resource that exists without ever touching data."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,name\n1,alpha\n2,beta\n")

    role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-crawler-trust-"),
        {"Service": "glue.amazonaws.com"},
        managed_policy_arns=[_MANAGED_POLICY],
    )

    db_name = ctx.unique_name("sim2real_crawler_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-crawler-")
    # CreateCrawler validates that the role is assumable synchronously, so a freshly created
    # role can bounce with "unable to assume" until IAM's propagation window closes; retry the
    # call itself against that documented eventual consistency rather than sleeping blindly.
    _create_crawler_with_retry(
        glue,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    glue.start_crawler(Name=crawler_name)
    final = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == _CRAWLER_TERMINAL_STATE,
        timeout_s=360,
        interval_s=15,
    )
    assert final["LastCrawl"]["Status"] == "SUCCEEDED", f"unexpected crawl result: {final.get('LastCrawl')}"

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly one crawled table, got {len(tables)}: {tables}"
    table = tables[0]
    assert table["StorageDescriptor"]["Location"] == f"s3://{bucket}/data/", (
        f"table location {table['StorageDescriptor']['Location']!r} does not point at the crawled prefix"
    )
    columns = {c["Name"].lower() for c in table["StorageDescriptor"]["Columns"]}
    assert columns == {"id", "name"}, f"expected columns {{'id', 'name'}}, got {columns}"


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("aws-glue-sim2real-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objs = resp.get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_role(
    ctx,
    iam,
    role_name: str,
    trust_principal: dict[str, Any],
    managed_policy_arns: list[str] | None = None,
    inline_policies: dict[str, dict] | None = None,
) -> str:
    trust_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc)["Role"]["Arn"]

    def _cleanup() -> None:
        for arn in managed_policy_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pname in (inline_policies or {}):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _create_crawler_with_retry(glue, retries: int = 6, delay: float = 10.0, **kwargs) -> None:
    """A freshly created IAM role can take a short time to become assumable by Glue;
    CreateCrawler validates assumability synchronously, so retry through that documented
    eventual-consistency window (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency)
    instead of sleeping blindly beforehand."""
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as e:
            if "unable to assume" in str(e).lower() and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
