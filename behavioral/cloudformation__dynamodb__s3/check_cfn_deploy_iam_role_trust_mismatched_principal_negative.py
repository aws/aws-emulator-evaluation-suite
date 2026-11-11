"""cfn-deploy-iam-role-trust-mismatched-principal-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-iam-role-trust-mismatched-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-created role trusting ec2.amazonaws.com cannot drive S3 replication: the config is
    accepted but the object never replicates; the same setup trusting s3.amazonaws.com works."""
    src_bad = _xname(ctx, "repl-src-bad")
    src_good = _xname(ctx, "repl-src-good")
    dest_good = _xname(ctx, "repl-dest-good")
    dest_bad = _xname(ctx, "repl-dest-bad")

    def _perm_policy(src: str, dest_bucket: str) -> dict[str, Any]:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                    "Resource": f"arn:aws:s3:::{src}",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObjectVersionForReplication",
                        "s3:GetObjectVersionAcl",
                        "s3:GetObjectVersionTagging",
                    ],
                    "Resource": f"arn:aws:s3:::{src}/*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"],
                    "Resource": f"arn:aws:s3:::{dest_bucket}/*",
                },
            ],
        }

    role_good_name = _xname(ctx, "repl-role-good")
    role_bad_name = _xname(ctx, "repl-role-bad")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ReplRoleGood": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_good_name,
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
                            {"PolicyName": "repl-perms", "PolicyDocument": _perm_policy(src_good, dest_good)}
                        ],
                    },
                },
                "ReplRoleBad": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_bad_name,
                        # Mismatched principal: this role can only be assumed by EC2
                        # instances, never by the S3 service itself.
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {"PolicyName": "repl-perms", "PolicyDocument": _perm_policy(src_bad, dest_bad)}
                        ],
                    },
                },
            },
            "Outputs": {
                "GoodRoleArn": {"Value": {"Fn::GetAtt": ["ReplRoleGood", "Arn"]}},
                "BadRoleArn": {"Value": {"Fn::GetAtt": ["ReplRoleBad", "Arn"]}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template)
    good_role_arn = stack["outputs"]["GoodRoleArn"]
    bad_role_arn = stack["outputs"]["BadRoleArn"]

    s3 = ctx.client("s3")
    for name in (src_bad, src_good, dest_good, dest_bad):
        s3.create_bucket(**_create_bucket_kwargs(ctx, name))
        ctx.on_cleanup(lambda n=name: _empty_and_delete_bucket(ctx, n))
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})

    # Configure replication with the MISMATCHED-trust role.
    s3.put_bucket_replication(
        Bucket=src_bad,
        ReplicationConfiguration={
            "Role": bad_role_arn,
            "Rules": [
                {
                    "ID": "rule-bad",
                    "Status": "Enabled",
                    "Prefix": "",
                    "Destination": {"Bucket": f"arn:aws:s3:::{dest_bad}"},
                }
            ],
        },
    )
    s3.put_object(Bucket=src_bad, Key="probe-bad.txt", Body=b"should-not-replicate")

    # --- Positive control: identical setup on a twin source, only the role's trust principal
    # changes. Its object is written after the mismatched one, so its arrival orders the absence.
    s3.put_bucket_replication(
        Bucket=src_good,
        ReplicationConfiguration={
            "Role": good_role_arn,
            "Rules": [
                {
                    "ID": "rule-good",
                    "Status": "Enabled",
                    "Prefix": "",
                    "Destination": {"Bucket": f"arn:aws:s3:::{dest_good}"},
                }
            ],
        },
    )
    s3.put_object(Bucket=src_good, Key="probe-good.txt", Body=b"should-replicate")

    def _dest_good_has_object():
        if (
            _error_code_or_success(lambda: s3.head_object(Bucket=dest_good, Key="probe-good.txt"))
            == _CALL_SUCCEEDED
        ):
            return True
        source = s3.head_object(Bucket=src_good, Key="probe-good.txt")
        if source.get("ReplicationStatus") == "FAILED":
            # S3 could not yet assume the just-created role: a new version retries replication.
            s3.put_object(Bucket=src_good, Key="probe-good.txt", Body=b"should-replicate")
        return False

    left = ctx.time_left()
    _poll_until(
        _dest_good_has_object,
        lambda ok: ok,
        timeout_s=180 if left is None else min(180, left),
        interval_s=2.0,
        description="replicated object appears in destination with correctly-trusted role",
    )
    code = _error_code_or_success(lambda: s3.head_object(Bucket=dest_bad, Key="probe-bad.txt"))
    assert code == "404", (
        f"the object written under the mismatched-trust role must never replicate: HeadObject on "
        f"the destination returned {code!r}, expected 404"
    )
    replicated_body = s3.get_object(Bucket=dest_good, Key="probe-good.txt")["Body"].read()
    assert replicated_body == b"should-replicate", (
        f"replicated object body mismatch: expected b'should-replicate', got {replicated_body!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


_CALL_SUCCEEDED = "<call succeeded>"


def _error_code_or_success(fn):
    """The AWS error code fn() raises, or _CALL_SUCCEEDED (a value no AWS error code can equal)
    when the call succeeds, so a success never reads as a missing or mismatched code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return _CALL_SUCCEEDED


def _create_bucket_kwargs(ctx, bucket_name: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        try:
            s3.delete_bucket_replication(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket_name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
