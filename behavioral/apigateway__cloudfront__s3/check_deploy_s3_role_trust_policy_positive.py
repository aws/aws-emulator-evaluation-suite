"""deploy-s3-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IAM role trusting s3.amazonaws.com is actually ASSUMED by S3's
    replication engine: an object PUT to the source bucket is replicated to the destination
    bucket using that role's permissions (not merely a role that exists unused)."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DestinationBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Fn::Sub": "${AWS::StackName}-dst"},
                        "VersioningConfiguration": {"Status": "Enabled"},
                    },
                },
                "ReplicationRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "s3.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "ReplicationPolicy",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                                            "Resource": {"Fn::Sub": "arn:aws:s3:::${AWS::StackName}-src"},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:GetObjectVersionForReplication",
                                                "s3:GetObjectVersionAcl",
                                                "s3:GetObjectVersionTagging",
                                            ],
                                            "Resource": {"Fn::Sub": "arn:aws:s3:::${AWS::StackName}-src/*"},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                                            "Resource": {"Fn::Sub": "arn:aws:s3:::${AWS::StackName}-dst/*"},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "SourceBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Fn::Sub": "${AWS::StackName}-src"},
                        "VersioningConfiguration": {"Status": "Enabled"},
                        "ReplicationConfiguration": {
                            "Role": {"Fn::GetAtt": ["ReplicationRole", "Arn"]},
                            "Rules": [
                                {
                                    "Id": "rule1",
                                    "Status": "Enabled",
                                    "Priority": 1,
                                    "Filter": {"Prefix": ""},
                                    "DeleteMarkerReplication": {"Status": "Disabled"},
                                    "Destination": {"Bucket": {"Fn::GetAtt": ["DestinationBucket", "Arn"]}},
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "SourceBucketName": {"Value": {"Ref": "SourceBucket"}},
                "DestinationBucketName": {"Value": {"Ref": "DestinationBucket"}},
            },
        }
    )

    result = _deploy_cfn(ctx, template)
    src = result["outputs"]["SourceBucketName"]
    dst = result["outputs"]["DestinationBucketName"]

    s3 = ctx.client("s3")
    # CloudFormation refuses to delete a non-empty bucket, so the stack's own delete-stack
    # cleanup (registered by _deploy_cfn, and thus LIFO-earlier) would otherwise strand both
    # versioned buckets. Register these emptiers after the stack's cleanup so LIFO runs them
    # first, before the stack deletion they must precede.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, src))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, dst))
    key = "rep-test.txt"
    body = b"replicate-me-" + ctx.unique_name("x").encode()
    s3.put_object(Bucket=src, Key=key, Body=body)

    def _dst_object():
        try:
            return s3.get_object(Bucket=dst, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise

    # S3 replication (without Replication Time Control) has no fixed completion SLA; see
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-time-control.html
    content = _poll_until(
        _dst_object,
        lambda c: c is not None,
        timeout_s=600,
        interval_s=10.0,
        description="replicated object appears in destination bucket",
    )
    assert content == body, f"expected replicated body {body!r}, got {content!r}"


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


def _empty_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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
