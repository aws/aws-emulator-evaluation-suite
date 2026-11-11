"""deploy-distribution-cfn-serves-live-traffic."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags


CHECK = "deploy-distribution-cfn-serves-live-traffic"
GROUP = "deploy"
SERVICES = ["cloudfront"]

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
  OriginAccessControl:
    Type: AWS::CloudFront::OriginAccessControl
    Properties:
      OriginAccessControlConfig:
        Name: !Sub "sim2real-oac-${AWS::StackName}"
        OriginAccessControlOriginType: s3
        SigningBehavior: always
        SigningProtocol: sigv4
  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Comment: sim2real deploy-distribution-cfn-serves-live-traffic
        DefaultCacheBehavior:
          TargetOriginId: s3origin
          ViewerProtocolPolicy: allow-all
          CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad
        Origins:
          - Id: s3origin
            DomainName: !GetAtt ContentBucket.RegionalDomainName
            OriginAccessControlId: !Ref OriginAccessControl
            S3OriginConfig:
              OriginAccessIdentity: ""
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
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed distribution with an S3+OAC origin actually serves the
    object over its cloudfront.net domain, not merely reaches CREATE_COMPLETE."""
    stack_name, outputs = _deploy_cfn_stack(ctx, _TEMPLATE)
    bucket = outputs["BucketName"]
    domain = outputs["DomainName"]

    s3 = ctx.client("s3")
    content = b"sim2real-deploy-check-original-content"
    s3.put_object(Bucket=bucket, Key="index.txt", Body=content, ContentType="text/plain")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="index.txt"))

    edge, route = ctx.endpoint_route(domain)
    status, body = _poll_http_get(f"{edge}/index.txt", route, expect_status=200, timeout_s=60.0, verify=ctx.http_verify)
    assert status == 200, f"expected 200 from live distribution, got {status}"
    assert body == content, f"distribution served {body!r}, expected origin content {content!r}"


# ===== helpers =====


def _deploy_cfn_stack(ctx, template_body: str):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cf-deploy-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cfn_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1200})
    outputs = {}
    for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return stack_name, outputs


def _delete_cfn_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    # The bucket's object cleanup is registered later, so it runs (LIFO) before this one.
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    # Bounded by the suite's 1800 s cleanup budget; disabling and deleting a distribution fits it.
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850})


def _poll_http_get(url: str, route: dict, expect_status: int, timeout_s: float = 60.0, interval_s: float = 3.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **route})
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=_https_context(verify)) as resp:
                last = (resp.status, resp.read())
        except urllib.error.HTTPError as exc:
            last = (exc.code, exc.read())
        except urllib.error.URLError:
            last = (None, b"")
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
