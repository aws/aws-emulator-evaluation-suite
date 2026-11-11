"""cfn-deploy-glue-crawler-s3-target-stack-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-crawler-s3-target-stack-positive"
GROUP = "deployment-order"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Glue crawler, targeting an S3 path created in the same stack, actually
    crawls the data and populates the Data Catalog with an inferred table after running."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    db_name = _glue_name(ctx, "db")
    crawler_name = _xname(ctx, "crawler")
    role_name = _xname(ctx, "role")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
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
                            "PolicyName": "s3read",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [
                                            {"Fn::Sub": "arn:aws:s3:::${Bucket}"},
                                            {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "Crawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": ["CrawlerRole", "GlueDatabase", "Bucket"],
                "Properties": {
                    "Name": crawler_name,
                    "Role": {"Fn::GetAtt": ["CrawlerRole", "Arn"]},
                    "DatabaseName": db_name,
                    "Targets": {
                        "S3Targets": [{"Path": {"Fn::Sub": "s3://${Bucket}/data/"}}]
                    },
                },
            },
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]

    body = b"id,name,value\n1,alice,100\n2,bob,200\n3,carol,300\n"
    s3.put_object(Bucket=bucket, Key="data/part-00000.csv", Body=body)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    # IAM role/policy propagation is eventually consistent (seconds, per IAM docs); rather than
    # an unconditional sleep, StartCrawler itself is retried with backoff until the role is
    # assumable, and the success assertion below is a bounded poll on the crawler's own state.
    _start_crawler_with_retry(ctx, crawler_name)

    crawler = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY",
        timeout_s=300,
        interval_s=10.0,
        description=f"crawler {crawler_name} to finish",
    )
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) == 1, f"expected exactly 1 catalog table, GetTables returned {len(tables)}: {tables}"
    columns = tables[0]["StorageDescriptor"]["Columns"]
    assert len(columns) == 3, f"expected 3 inferred columns (id,name,value), got {len(columns)}: {columns}"
    location = tables[0]["StorageDescriptor"]["Location"]
    expected_location = f"s3://{bucket}/data/"
    assert location == expected_location, f"expected table Location {expected_location!r}, got {location!r}"


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


def _glue_name(ctx: Any, kind: str) -> str:
    return _xname(ctx, kind).replace("-", "_")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _start_crawler_with_retry(ctx, crawler_name: str, *, attempts: int = 5, backoff_s: float = 15.0) -> None:
    glue = ctx.client("glue")
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            glue.start_crawler(Name=crawler_name)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(backoff_s)
    if last_exc is not None:
        raise last_exc


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
