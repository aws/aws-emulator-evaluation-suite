"""deploy-glue-crawler-cfn-runs-and-populates-catalog."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-glue-crawler-cfn-runs-and-populates-catalog"
GROUP = "deploy"
SERVICES = ["glue"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DatabaseName:
    Type: String
  CrawlerName:
    Type: String
  RoleArn:
    Type: String
  S3TargetPath:
    Type: String
Resources:
  GlueDatabase:
    Type: AWS::Glue::Database
    Properties:
      CatalogId: !Ref AWS::AccountId
      DatabaseInput:
        Name: !Ref DatabaseName
  GlueCrawler:
    Type: AWS::Glue::Crawler
    DependsOn: GlueDatabase
    Properties:
      Name: !Ref CrawlerName
      Role: !Ref RoleArn
      DatabaseName: !Ref DatabaseName
      Targets:
        S3Targets:
          - Path: !Ref S3TargetPath
Outputs:
  CrawlerNameOut:
    Value: !Ref CrawlerName
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A crawler deployed via AWS::Glue::Crawler, when started, actually crawls the
    S3 source and creates real tables (with inferred schema) in the Data Catalog --
    not merely a metadata object that never runs."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glue-crawl-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    key = "data/sample.csv"
    csv_body = "id,name,value\n1,alpha,10\n2,beta,20\n3,gamma,30\n"
    s3.put_object(Bucket=bucket, Key=key, Body=csv_body.encode("utf-8"))

    role_arn = _create_crawler_role(ctx, iam, bucket)

    db_name = ctx.unique_name("sim2real-glue-crdb-")
    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    stack_name = ctx.unique_name("sim2real-glue-crstack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 440})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "DatabaseName", "ParameterValue": db_name},
            {"ParameterKey": "CrawlerName", "ParameterValue": crawler_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "S3TargetPath", "ParameterValue": f"s3://{bucket}/data/"},
        ],
    )
    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    # IAM role propagation can lag; retry StartCrawler for a bit.
    def _start() -> bool:
        try:
            glue.start_crawler(Name=crawler_name)
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "CrawlerRunningException"):
                return False
            raise

    _poll_until(_start, lambda started: started, timeout_s=60, interval_s=5)

    def _probe() -> dict:
        return glue.get_crawler(Name=crawler_name)["Crawler"]

    crawler = _poll_until(
        _probe, lambda c: c["State"] == "READY" and "LastCrawl" in c,
        timeout_s=420, interval_s=10,
    )
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "crawler did not create any tables in the Catalog"
    columns = {c["Name"] for c in tables[0]["StorageDescriptor"]["Columns"]}
    assert {"id", "name", "value"}.issubset(columns), columns


# ===== helpers =====

def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_crawler_role(ctx: Any, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-glue-crawl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    inline_policy_name = "sim2real-s3-read"
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    return role_arn


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool],
                 timeout_s: float, interval_s: float) -> Any:
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
