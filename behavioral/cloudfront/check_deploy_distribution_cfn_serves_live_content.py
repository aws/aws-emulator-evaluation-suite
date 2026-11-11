"""deploy-distribution-cfn-serves-live-content."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-distribution-cfn-serves-live-content"
GROUP = "deploy"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFront distribution deployed via CloudFormation reaches Deployed and serves the object
    through its domain name, not just CREATE_COMPLETE; its private origin bucket admits only that
    distribution, through an origin access control."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    cloudfront = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-cf-origin-").lower().replace("_", "-")
    content = ctx.unique_name("sim2real-live-content-")

    _create_private_bucket(ctx, bucket)
    s3.put_object(Bucket=bucket, Key="index.html", Body=content.encode("utf-8"), ContentType="text/plain")

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    stack_name = ctx.unique_name("sim2real-cf-stack-")
    template = {
        "Resources": {
            "Oac": {
                "Type": "AWS::CloudFront::OriginAccessControl",
                "Properties": {
                    "OriginAccessControlConfig": {
                        "Name": stack_name,
                        "OriginAccessControlOriginType": "s3",
                        "SigningBehavior": "always",
                        "SigningProtocol": "sigv4",
                    }
                },
            },
            "OriginPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": bucket,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": "s3:GetObject",
                                "Resource": f"arn:aws:s3:::{bucket}/*",
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceArn": {
                                            "Fn::Sub": "arn:${AWS::Partition}:cloudfront::"
                                            "${AWS::AccountId}:distribution/${Dist}"
                                        }
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "Dist": {
                "Type": "AWS::CloudFront::Distribution",
                "Properties": {
                    "DistributionConfig": {
                        "Enabled": True,
                        "Comment": "sim2real deploy check",
                        "Origins": [
                            {
                                "Id": "s3origin",
                                "DomainName": origin_domain,
                                "OriginAccessControlId": {"Fn::GetAtt": ["Oac", "Id"]},
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                            }
                        ],
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "s3origin",
                            "ViewerProtocolPolicy": "allow-all",
                            # Managed "CachingDisabled" policy -- forces every fetch to the origin.
                            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                        },
                    }
                },
            }
        },
        "Outputs": {
            "DistId": {"Value": {"Ref": "Dist"}},
            "DistDomain": {"Value": {"Fn::GetAtt": ["Dist", "DomainName"]}},
        },
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _wait_stack_status(ctx, stack_name, "CREATE_COMPLETE", timeout_s=1200)

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    dist_id = outputs["DistId"]
    domain = outputs["DistDomain"]

    status = _poll_until(
        lambda: cloudfront.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=20,
    )
    assert status == "Deployed", f"distribution never reached Deployed, last status={status}"

    # GetDistributionConfig must also reflect the deployed origin, not just the create input.
    cfg = cloudfront.get_distribution_config(Id=dist_id)["DistributionConfig"]
    actual_origin = cfg["Origins"]["Items"][0]["DomainName"]
    assert actual_origin == origin_domain, f"expected origin domain {origin_domain!r}, got {actual_origin!r}"

    body = _poll_fetch(ctx, f"http://{domain}/index.html", timeout_s=300, interval_s=10)
    assert body == content, f"expected live content {content!r}, got {body!r}"


def _create_private_bucket(ctx, bucket: str) -> None:
    """A bucket with every Block Public Access setting on; only the stack's policy opens it."""
    s3 = ctx.client("s3")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _wait_stack_status(ctx, stack_name, target_status, timeout_s=900.0, interval_s=15.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == target_status:
            return status
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered {status} while waiting for {target_status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {target_status}, last status={status}")


def _delete_stack_and_wait(ctx, stack_name) -> None:
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
        timeout_s=1800,
        interval_s=20,
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


def _poll_fetch(ctx, url, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10, context=_https_context(ctx.http_verify)) as resp:  # noqa: S310
                return resp.read().decode("utf-8")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"never got a successful response from {url}: {last_err}")


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
