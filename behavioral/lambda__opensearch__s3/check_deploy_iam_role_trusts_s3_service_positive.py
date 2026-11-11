"""deploy-iam-role-trusts-s3-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-role-trusts-s3-service-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IAM role trusting s3.amazonaws.com is the role S3 itself assumes to
    replicate objects into a destination bucket -- verified by an end-to-end replication."""
    source_name = _xname(ctx, "src").lower()
    dest_name = _xname(ctx, "dst").lower()
    source_arn = f"arn:aws:s3:::{source_name}"
    dest_arn = f"arn:aws:s3:::{dest_name}"
    role_name = _xname(ctx, "replrole")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ReplicationRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
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
                                "PolicyName": "replication",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:GetReplicationConfiguration",
                                                "s3:ListBucket",
                                            ],
                                            "Resource": source_arn,
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:GetObjectVersionForReplication",
                                                "s3:GetObjectVersionAcl",
                                                "s3:GetObjectVersionTagging",
                                            ],
                                            "Resource": f"{source_arn}/*",
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:ReplicateObject",
                                                "s3:ReplicateDelete",
                                                "s3:ReplicateTags",
                                            ],
                                            "Resource": f"{dest_arn}/*",
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "DestBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": dest_name,
                        "VersioningConfiguration": {"Status": "Enabled"},
                    },
                },
                "SourceBucket": {
                    "Type": "AWS::S3::Bucket",
                    "DependsOn": ["DestBucket", "ReplicationRole"],
                    "Properties": {
                        "BucketName": source_name,
                        "VersioningConfiguration": {"Status": "Enabled"},
                        "ReplicationConfiguration": {
                            "Role": {"Fn::GetAtt": ["ReplicationRole", "Arn"]},
                            "Rules": [
                                {
                                    "Id": "replicate-all",
                                    "Status": "Enabled",
                                    "Priority": 1,
                                    "Filter": {"Prefix": ""},
                                    "DeleteMarkerReplication": {"Status": "Disabled"},
                                    "Destination": {"Bucket": dest_arn},
                                }
                            ],
                        },
                    },
                },
            },
        }
    )

    _deploy_cfn(ctx, template, timeout_s=300.0)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, dest_name))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, source_name))

    # Independent read of the *deployed* role, at the resource the check's name makes a
    # claim about -- replication succeeding is consistent with, but does not by itself
    # demonstrate, that CFN actually wired the trust statement we asked for.
    iam = ctx.client("iam")
    deployed_trust = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    trusted_principal = deployed_trust["Statement"][0]["Principal"]["Service"]
    assert trusted_principal == "s3.amazonaws.com", (
        f"expected deployed role {role_name!r} to trust s3.amazonaws.com, "
        f"got principal={trusted_principal!r}"
    )

    s3 = ctx.client("s3")
    body = b"replicate-me-" + source_name.encode()
    key = "objects/payload.txt"
    s3.put_object(Bucket=source_name, Key=key, Body=body)

    # S3 replication has no fixed SLA for a plain (non-RTC) rule -- most objects replicate
    # within minutes. Poll a generous window for the object to APPEAR in the destination.
    def _probe():
        try:
            return s3.get_object(Bucket=dest_name, Key=key)["Body"].read()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchKey", "404"):
                return None
            raise

    replicated_body = _poll_until(
        _probe,
        lambda b: b is not None,
        timeout_s=300.0,
        interval_s=10.0,
        description=f"replicated object {key} in {dest_name}",
    )
    assert replicated_body == body, (
        f"expected replicated object body {body!r} in {dest_name}, got {replicated_body!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(ctx, bucket_name: str) -> None:
    """Delete all object versions/delete-markers so a CFN-managed bucket can be deleted."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        reasons = []
        try:
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]:
                if "FAILED" in e.get("ResourceStatus", ""):
                    reasons.append(
                        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
                    )
        except ClientError:
            pass
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; reasons={reasons}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
