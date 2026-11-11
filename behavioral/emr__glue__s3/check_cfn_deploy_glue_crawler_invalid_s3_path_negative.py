"""cfn-deploy-glue-crawler-invalid-s3-path-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-crawler-invalid-s3-path-negative"
GROUP = "overly-permissive"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose Glue crawler targets a path in a nonexistent bucket rolls back on the crawler's S3-target
    404 and leaves no database, while a same-shape stack targeting a populated path deploys, crawls to
    SUCCEEDED and catalogues one table."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    role_name = _xname(ctx, "role")
    db_valid = _glue_name(ctx, "db_valid")
    db_invalid = _glue_name(ctx, "db_invalid")
    crawler_valid = _xname(ctx, "crawler-valid")
    crawler_invalid = _xname(ctx, "crawler-invalid")
    # Never created anywhere -- this bucket genuinely does not exist.
    nonexistent_bucket = _xname(ctx, "nonexistent-bucket")

    valid_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ValidBucket": {"Type": "AWS::S3::Bucket"},
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
                                            {"Fn::Sub": "arn:aws:s3:::${ValidBucket}"},
                                            {"Fn::Sub": "arn:aws:s3:::${ValidBucket}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "ValidDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_valid},
                },
            },
            "ValidCrawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": ["CrawlerRole", "ValidDatabase", "ValidBucket"],
                "Properties": {
                    "Name": crawler_valid,
                    "Role": {"Fn::GetAtt": ["CrawlerRole", "Arn"]},
                    "DatabaseName": db_valid,
                    "Targets": {
                        "S3Targets": [{"Path": {"Fn::Sub": "s3://${ValidBucket}/data/"}}]
                    },
                },
            },
        },
        "Outputs": {
            "ValidBucketName": {"Value": {"Ref": "ValidBucket"}},
            "CrawlerRoleArn": {"Value": {"Fn::GetAtt": ["CrawlerRole", "Arn"]}},
        },
    }

    valid_result = _deploy_cfn(ctx, json.dumps(valid_template))
    valid_bucket = valid_result["outputs"]["ValidBucketName"]
    role_arn = valid_result["outputs"]["CrawlerRoleArn"]

    body = b"id,name,value\n1,alice,100\n2,bob,200\n3,carol,300\n"
    s3.put_object(Bucket=valid_bucket, Key="data/part-00000.csv", Body=body)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, valid_bucket))

    # IAM role/policy propagation is eventually consistent (seconds, per IAM docs); rather than
    # a blind pre-sleep, _start_crawler_with_retry itself bounds-and-backs-off on that window.
    _start_crawler_with_retry(ctx, crawler_valid)
    valid_state = _poll_until(
        lambda: glue.get_crawler(Name=crawler_valid)["Crawler"],
        lambda c: c["State"] == "READY",
        timeout_s=300,
        interval_s=10.0,
        description=f"crawler {crawler_valid} to finish",
    )

    # Positive control: crawler on a real, populated path, deployed via CFN, actually runs and
    # creates a table -- proves the account, role and CFN wiring are otherwise healthy.
    assert valid_state["LastCrawl"]["Status"] == "SUCCEEDED", valid_state["LastCrawl"]
    valid_tables = glue.get_tables(DatabaseName=db_valid)["TableList"]
    assert len(valid_tables) == 1, f"expected 1 table in {db_valid}, got {len(valid_tables)}: {valid_tables}"

    # Negative (always-invalid-input, no restore leg by construction): a same-shape stack whose
    # crawler targets a bucket that never existed is rejected by CloudFormation's own
    # AWS::Glue::Crawler creation-time S3-target validation. The stack never reaches
    # CREATE_COMPLETE -- it is not that the crawler runs and later fails.
    invalid_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"CrawlerRoleArn": {"Type": "String"}},
        "Resources": {
            "InvalidDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_invalid},
                },
            },
            "InvalidCrawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": ["InvalidDatabase"],
                "Properties": {
                    "Name": crawler_invalid,
                    "Role": {"Ref": "CrawlerRoleArn"},
                    "DatabaseName": db_invalid,
                    "Targets": {
                        "S3Targets": [{"Path": f"s3://{nonexistent_bucket}/data/"}]
                    },
                },
            },
        },
    }
    invalid_deploy = _deploy_cfn_expect_rejection(
        ctx, json.dumps(invalid_template), parameters={"CrawlerRoleArn": role_arn}
    )
    assert invalid_deploy["status"] in {"ROLLBACK_COMPLETE", "CREATE_FAILED"}, invalid_deploy
    reasons = " ".join(invalid_deploy["failures"]).lower()
    assert "404" in reasons and "s3 target" in reasons, (
        f"expected the crawler's own S3-target 404 validation in the failure reason, got: "
        f"{invalid_deploy['failures']}"
    )

    # Effect-absent, independent read at the destination: CloudFormation rolled the failed stack
    # back, so the database it would have owned does not exist either.
    try:
        glue.get_database(Name=db_invalid)
        raise AssertionError(f"expected database {db_invalid} to not exist after stack rollback")
    except glue.exceptions.EntityNotFoundException as exc:
        message = exc.response["Error"]["Message"]
        assert message == f"Database {db_invalid} not found.", (
            f"expected the message 'Database {db_invalid} not found.', got {message!r}"
        )


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


def _stack_failure_events(cfn, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"] in {"CREATE_FAILED", "ROLLBACK_FAILED"}
    ]


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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {_stack_failure_events(cfn, name)}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _deploy_cfn_expect_rejection(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    """Like `_deploy_cfn`, but for a stack this check expects CloudFormation to refuse: it
    returns the terminal status and failure reasons instead of raising, so the caller can assert
    on the specific rejection rather than only on non-success."""
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
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    return {"stack_name": name, "status": status, "failures": _stack_failure_events(cfn, name)}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
