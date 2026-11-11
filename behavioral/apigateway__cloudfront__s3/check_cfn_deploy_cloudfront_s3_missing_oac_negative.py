"""cfn-deploy-cloudfront-s3-missing-oac-negative."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cfn-deploy-cloudfront-s3-missing-oac-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFront distribution with an OAC on its S3 origin but no matching bucket policy statement cannot
    read the bucket; updating the stack to add the statement makes the distribution serve the object."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    template = json.dumps(_template())
    deployed = _deploy_cfn(
        ctx, template, teardown_deadline, parameters={"AttachPolicy": "false"}, timeout_s=1500.0
    )
    stack_name = deployed["stack_name"]
    bucket_name = deployed["outputs"]["BucketName"]
    domain = deployed["outputs"]["DistributionDomainName"]

    s3 = ctx.client("s3")
    secret_body = b"secret-content"
    s3.put_object(Bucket=bucket_name, Key="index.html", Body=secret_body, ContentType="text/plain")

    def _fetch():
        url, headers = ctx.endpoint_route(f"{domain}/index.html")
        return _http_get(url, headers=headers, verify=ctx.http_verify)

    # Give CloudFront's response a few tries in case of a fresh distribution's first-hit
    # latency, but the outcome (no bucket permission) should be immediate and stable.
    status, content = _poll_until(
        _fetch,
        lambda r: r[0] is not None,
        timeout_s=60.0,
        interval_s=5.0,
        description="CloudFront responding (even with an error) to the missing-policy origin",
    )
    assert status == 403, f"expected 403 with no bucket policy granted, got {status}: {content!r}"
    assert content != secret_body.decode("utf-8"), "object content leaked without a bucket policy"

    # Positive control on the SAME distribution: add the OAC bucket-policy statement via a
    # stack update and confirm access is now granted -- proving the policy, not something
    # else, was the single differentiating factor.
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "AttachPolicy", "ParameterValue": "true"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=600.0,
        interval_s=5.0,
        description=f"CFN stack {stack_name} update to attach bucket policy",
    )
    assert final_status == "UPDATE_COMPLETE", f"stack update ended in {final_status}"

    status2, content2 = _poll_until(
        _fetch,
        lambda r: r[0] == 200,
        timeout_s=120.0,
        interval_s=5.0,
        description="CloudFront serving the object once the bucket policy is attached",
    )
    assert status2 == 200 and content2 == secret_body.decode("utf-8"), (
        f"positive control failed: expected 200/secret-content, got {status2}: {content2!r}"
    )


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AttachPolicy": {
                "Type": "String",
                "AllowedValues": ["true", "false"],
                "Default": "false",
            }
        },
        "Conditions": {"AttachOAC": {"Fn::Equals": [{"Ref": "AttachPolicy"}, "true"]}},
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            },
            "OAC": {
                "Type": "AWS::CloudFront::OriginAccessControl",
                "Properties": {
                    "OriginAccessControlConfig": {
                        "Name": {"Fn::Sub": "${AWS::StackName}-oac"},
                        "OriginAccessControlOriginType": "s3",
                        "SigningBehavior": "always",
                        "SigningProtocol": "sigv4",
                    }
                },
            },
            "Distribution": {
                "Type": "AWS::CloudFront::Distribution",
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": True,
                        "DefaultRootObject": "index.html",
                        "Origins": [
                            {
                                "Id": "S3Origin",
                                "DomainName": {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]},
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                                "OriginAccessControlId": {"Fn::GetAtt": ["OAC", "Id"]},
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "S3Origin",
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                            "AllowedMethods": ["GET", "HEAD"],
                        },
                    }
                },
            },
            "BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Condition": "AttachOAC",
                "Properties": {
                    "Bucket": {"Ref": "Bucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowCloudFrontServicePrincipal",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": "s3:GetObject",
                                "Resource": {"Fn::Sub": "${Bucket.Arn}/*"},
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceArn": {
                                            "Fn::Sub": "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribution.Id}"
                                        }
                                    }
                                },
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
            "DistributionId": {"Value": {"Ref": "Distribution"}},
        },
    }


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"
_CLEANUP_S = 1800.0


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


def _empty_stack_buckets(ctx, stack_name: str) -> None:
    """CloudFormation refuses to delete a non-empty S3 bucket, which would strand the whole
    stack in DELETE_FAILED -- so empty every bucket this stack owns before deleting it."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    try:
        resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    for resource in resources:
        if resource["ResourceType"] != "AWS::S3::Bucket":
            continue
        bucket = resource["PhysicalResourceId"]
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objects:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    """Delete a CFN stack and wait until it is gone; DELETE_FAILED or the deadline raises."""
    cfn = ctx.client("cloudformation")
    _empty_stack_buckets(ctx, stack_name)
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S - 120.0)
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

    # Deleting the stack's distribution takes many minutes (it is disabled and propagated first),
    # so every stack teardown of the run shares one deadline inside the suite's cleanup budget.
    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=max(deadline - time.monotonic(), 0.0),
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended DELETE_FAILED")


def _deploy_cfn(
    ctx,
    template,
    teardown_deadline,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _http_get(url: str, timeout: float = 10.0, headers: dict | None = None, verify=True) -> tuple[int | None, str]:
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return None, str(e)


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
