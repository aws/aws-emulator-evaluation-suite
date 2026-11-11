"""deploy-cache-policy-cfn-enforced-on-distribution."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags


CHECK = "deploy-cache-policy-cfn-enforced-on-distribution"
GROUP = "deploy"
SERVICES = ["cloudfront"]

_TTL_SECONDS = 10

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ContentBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: sim2real-check
          Value: deploy-cache-policy-cfn-enforced-on-distribution
  OriginAccessControl:
    Type: AWS::CloudFront::OriginAccessControl
    Properties:
      OriginAccessControlConfig:
        Name: !Sub "sim2real-oac-${AWS::StackName}"
        OriginAccessControlOriginType: s3
        SigningBehavior: always
        SigningProtocol: sigv4
  FixedTtlCachePolicy:
    Type: AWS::CloudFront::CachePolicy
    Properties:
      CachePolicyConfig:
        Name: !Sub "sim2real-ttl10-${AWS::StackName}"
        DefaultTTL: 10
        MaxTTL: 10
        MinTTL: 10
        ParametersInCacheKeyAndForwardedToOrigin:
          CookiesConfig:
            CookieBehavior: none
          HeadersConfig:
            HeaderBehavior: none
          QueryStringsConfig:
            QueryStringBehavior: none
          EnableAcceptEncodingGzip: false
  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Comment: sim2real deploy-cache-policy-cfn-enforced-on-distribution
        DefaultCacheBehavior:
          TargetOriginId: s3origin
          ViewerProtocolPolicy: allow-all
          CachePolicyId: !Ref FixedTtlCachePolicy
        Origins:
          - Id: s3origin
            DomainName: !GetAtt ContentBucket.RegionalDomainName
            OriginAccessControlId: !Ref OriginAccessControl
            S3OriginConfig:
              OriginAccessIdentity: ""
      Tags:
        - Key: sim2real-check
          Value: deploy-cache-policy-cfn-enforced-on-distribution
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref ContentBucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudfront.amazonaws.com
            Action: s3:GetObject
            Resource: !Sub "${ContentBucket.Arn}/*"
            Condition:
              StringEquals:
                aws:SourceArn: !Sub "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribution}"
Outputs:
  BucketName:
    Value: !Ref ContentBucket
  DistributionId:
    Value: !Ref Distribution
  DomainName:
    Value: !GetAtt Distribution.DomainName
  CachePolicyId:
    Value: !Ref FixedTtlCachePolicy
"""


# timing:real-time — ttl: 10 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A cache policy with a fixed 10s TTL, deployed via CloudFormation and attached to a
    distribution, is actually enforced on repeated fetches: a mutated origin object stays
    stale through the TTL window and only refreshes once the TTL has elapsed."""
    stack_name, outputs = _deploy_cfn_stack(ctx, _TEMPLATE)
    bucket = outputs["BucketName"]
    domain = outputs["DomainName"]
    cache_policy_id = outputs["CachePolicyId"]

    cf = ctx.client("cloudfront")
    persisted = cf.get_cache_policy_config(Id=cache_policy_id)["CachePolicyConfig"]
    assert persisted["DefaultTTL"] == _TTL_SECONDS, (
        f"expected DefaultTTL={_TTL_SECONDS}, got {persisted['DefaultTTL']!r}"
    )
    assert persisted["MinTTL"] == _TTL_SECONDS, (
        f"expected MinTTL={_TTL_SECONDS}, got {persisted['MinTTL']!r}"
    )
    assert persisted["MaxTTL"] == _TTL_SECONDS, (
        f"expected MaxTTL={_TTL_SECONDS}, got {persisted['MaxTTL']!r}"
    )

    s3 = ctx.client("s3")
    key = "ttl-object.txt"
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    s3.put_object(Bucket=bucket, Key=key, Body=b"content-v1", ContentType="text/plain")

    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/{key}"
    status, body = _poll_http_get(url, route, expect_status=200, timeout_s=60.0, verify=ctx.http_verify)
    assert status == 200 and body == b"content-v1", (
        f"expected initial 200 content-v1, got status={status!r} body={body!r}"
    )

    # Mutate the origin while the object should still be within the cache policy's TTL
    # window (https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html).
    s3.put_object(Bucket=bucket, Key=key, Body=b"content-v2", ContentType="text/plain")
    status, body = _http_get(url, route, verify=ctx.http_verify)
    assert status == 200 and body == b"content-v1", (
        f"expected TTL-enforced stale content-v1 immediately after origin mutation, got {body!r}"
    )

    # Poll past the TTL window for the cache policy to actually let the refresh through.
    deadline = time.monotonic() + _TTL_SECONDS + 90.0
    refreshed = False
    while time.monotonic() < deadline:
        status, body = _http_get(url, route, verify=ctx.http_verify)
        if status == 200 and body == b"content-v2":
            refreshed = True
            break
        time.sleep(2.0)
    assert refreshed, "cache policy TTL expired but distribution never served refreshed content"


# ===== helpers =====


def _deploy_cfn_stack(ctx, template_body: str):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cf-cp-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _delete_cfn_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1200})
    outputs = {}
    for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return stack_name, outputs


def _delete_cfn_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    # Bounded by the suite's 1800 s cleanup budget; disabling and deleting a distribution fits it.
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850})


def _http_get(url: str, headers: dict, timeout: float = 10.0, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _poll_http_get(url: str, headers: dict, expect_status: int, timeout_s: float = 60.0, interval_s: float = 3.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        last = _http_get(url, headers, verify=verify)
        if last[0] == expect_status:
            return last
        time.sleep(interval_s)
    return last


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
