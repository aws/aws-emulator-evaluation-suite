"""cfn-stack-update-cloudfront-origin-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cfn-stack-update-cloudfront-origin-positive"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Updating a CFN stack to repoint CloudFront's S3 origin at a different bucket is
    observable in subsequent distribution requests -- old content stops being served and
    new-origin content starts."""
    template = json.dumps(_template())
    deployed = _deploy_cfn(
        ctx, template, parameters={"ActiveBucket": "A"}, timeout_s=1500.0
    )
    stack_name = deployed["stack_name"]
    bucket_a = deployed["outputs"]["BucketAName"]
    bucket_b = deployed["outputs"]["BucketBName"]
    domain = deployed["outputs"]["DistributionDomainName"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_a, Key="index.html", Body=b"origin-a-content", ContentType="text/plain")
    s3.put_object(Bucket=bucket_b, Key="index.html", Body=b"origin-b-content", ContentType="text/plain")
    # CloudFormation refuses to delete a non-empty bucket, so the stack's own DeleteStack
    # (registered by _deploy_cfn) would end in DELETE_FAILED and leak both buckets forever.
    # Cleanups run LIFO, so registering this after _deploy_cfn makes it run first.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_a))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_b))

    def _fetch():
        url, headers = ctx.endpoint_route(f"{domain}/index.html")
        return _http_get(url, headers=headers, verify=ctx.http_verify)

    status, content = _poll_until(
        _fetch,
        lambda r: r[0] == 200,
        timeout_s=240.0,
        interval_s=5.0,
        description="CloudFront serving bucket A content",
    )
    assert status == 200 and content == "origin-a-content", f"unexpected initial body: {content!r}"

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "ActiveBucket", "ParameterValue": "B"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=1500.0,
        interval_s=5.0,
        description=f"CFN stack {stack_name} update",
    )
    assert final_status == "UPDATE_COMPLETE", f"stack update ended in {final_status}"

    status2, content2 = _poll_until(
        _fetch,
        lambda r: r[0] == 200 and r[1] == "origin-b-content",
        timeout_s=240.0,
        interval_s=5.0,
        description="CloudFront serving bucket B content after origin switch",
    )
    assert status2 == 200 and content2 == "origin-b-content", f"unexpected body post-update: {content2!r}"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ActiveBucket": {
                "Type": "String",
                "AllowedValues": ["A", "B"],
                "Default": "A",
            }
        },
        "Conditions": {"IsBucketA": {"Fn::Equals": [{"Ref": "ActiveBucket"}, "A"]}},
        "Resources": {
            "BucketA": {
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
            "BucketB": {
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
                                "Id": "ActiveOrigin",
                                "DomainName": {
                                    "Fn::If": [
                                        "IsBucketA",
                                        {"Fn::GetAtt": ["BucketA", "RegionalDomainName"]},
                                        {"Fn::GetAtt": ["BucketB", "RegionalDomainName"]},
                                    ]
                                },
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                                "OriginAccessControlId": {"Fn::GetAtt": ["OAC", "Id"]},
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "ActiveOrigin",
                            "ViewerProtocolPolicy": "redirect-to-https",
                            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                            "AllowedMethods": ["GET", "HEAD"],
                        },
                    }
                },
            },
            "BucketPolicyA": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "BucketA"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowCloudFrontServicePrincipal",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": "s3:GetObject",
                                "Resource": {"Fn::Sub": "${BucketA.Arn}/*"},
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
            "BucketPolicyB": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "BucketB"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowCloudFrontServicePrincipal",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": "s3:GetObject",
                                "Resource": {"Fn::Sub": "${BucketB.Arn}/*"},
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
            "BucketAName": {"Value": {"Ref": "BucketA"}},
            "BucketBName": {"Value": {"Ref": "BucketB"}},
            "DistributionDomainName": {"Value": {"Fn::GetAtt": ["Distribution", "DomainName"]}},
            "DistributionId": {"Value": {"Ref": "Distribution"}},
        },
    }


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


def _empty_bucket(ctx: Any, bucket_name: str) -> None:
    """Delete every object version in a bucket (teardown; errors swallowed by on_cleanup)."""
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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
