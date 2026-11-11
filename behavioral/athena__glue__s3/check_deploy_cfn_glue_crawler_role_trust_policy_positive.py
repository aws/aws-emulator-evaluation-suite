"""deploy-cfn-glue-crawler-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-glue-crawler-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed IAM role for a Glue crawler trusts glue.amazonaws.com, and the crawler
    actually assumes it and catalogs the S3 data into a real table."""
    bucket_name = _xname(ctx, "crawl-bkt")
    role_name = _xname(ctx, "crawler-role")
    db_name = _sql_name(ctx, "crawldb")
    crawler_name = _xname(ctx, "crawler")

    template = {
        "Resources": {
            "DataBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name, "Tags": _xsvc_tags_kv()},
            },
            "CrawlerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "glue.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "s3-data-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [
                                            {"Fn::GetAtt": ["DataBucket", "Arn"]},
                                            {"Fn::Sub": "${DataBucket.Arn}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": _xsvc_tags_kv(),
                },
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "GlueCrawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": ["CrawlerRole", "GlueDatabase", "DataBucket"],
                "Properties": {
                    "Name": crawler_name,
                    "Role": {"Fn::GetAtt": ["CrawlerRole", "Arn"]},
                    "DatabaseName": {"Ref": "GlueDatabase"},
                    "Targets": {"S3Targets": [{"Path": f"s3://{bucket_name}/data/"}]},
                    "Tags": _xsvc_resource_tags(),
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    principals: list[str] = []
    for stmt in trust_doc["Statement"]:
        svc = stmt.get("Principal", {}).get("Service")
        principals.extend(svc if isinstance(svc, list) else [svc])
    assert "glue.amazonaws.com" in principals, trust_doc

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_name, Key="data/sample.csv", Body=b"1,alpha\n2,beta\n")
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    glue = ctx.client("glue")
    glue.start_crawler(Name=crawler_name)
    crawler = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY",
        timeout_s=600,
        interval_s=10.0,
        description=f"crawler {crawler_name} finished run",
    )
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler.get("LastCrawl")

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, tables
    table = tables[0]
    location = table["StorageDescriptor"]["Location"].rstrip("/")
    assert location == f"s3://{bucket_name}/data", table
    columns = table["StorageDescriptor"]["Columns"]
    assert len(columns) >= 2, columns


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _sql_name(ctx: Any, kind: str) -> str:
    """A Glue/Athena-identifier-safe unique name (underscores, no hyphens)."""
    return _xname(ctx, kind).replace("-", "_")


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    token = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket_name}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        objs = resp.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
