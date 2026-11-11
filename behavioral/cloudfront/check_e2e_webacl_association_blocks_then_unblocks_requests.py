"""e2e-webacl-association-blocks-then-unblocks-requests."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags


CHECK = "e2e-webacl-association-blocks-then-unblocks-requests"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Associating a blocking WAF web ACL with a distribution causes subsequent viewer
    requests to be blocked (403); disassociating restores successful (200) requests."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-cf-waf-").replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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

    oac_id = _create_oac(ctx)
    dist_id, etag, dist = _create_distribution(ctx, f"{bucket}.s3.{ctx.region}.amazonaws.com", oac_id)
    dist_arn = dist["ARN"]

    import json

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudfront.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {"StringEquals": {"aws:SourceArn": dist_arn}},
                    }
                ],
            }
        ),
    )

    resp = _wait_distribution_deployed(ctx, dist_id)
    domain = resp["Distribution"]["DomainName"]
    etag = resp["ETag"]

    key = "ok.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"ok", ContentType="text/plain")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/{key}"

    status, body = _poll_http_get(url, route, 200, timeout_s=90.0, verify=ctx.http_verify)
    assert status == 200 and body == b"ok", "baseline fetch before any web ACL must succeed"

    web_acl_arn = _create_blocking_web_acl(ctx)

    assoc = cf.associate_distribution_web_acl(Id=dist_id, WebACLArn=web_acl_arn, IfMatch=etag)
    etag = assoc["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    etag = resp["ETag"]

    blocked = _poll_until_status(url, route, 403, timeout_s=600.0, verify=ctx.http_verify)
    assert blocked, "web ACL was associated but requests were never blocked with 403"

    disassoc = cf.disassociate_distribution_web_acl(Id=dist_id, IfMatch=etag)
    etag = disassoc["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)

    status, body = _poll_http_get(url, route, 200, timeout_s=600.0, verify=ctx.http_verify)
    assert status == 200 and body == b"ok", (
        "web ACL was disassociated but requests were never restored to 200"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_oac(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": ctx.unique_name("sim2real-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))
    return oac_id


def _delete_oac(ctx, oac_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _create_distribution(ctx, bucket_regional_domain: str, oac_id: str):
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real e2e-webacl-association-blocks-then-unblocks-requests",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3origin",
                    "DomainName": bucket_regional_domain,
                    "OriginAccessControlId": oac_id,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id, resp["ETag"], dist


def _create_blocking_web_acl(ctx) -> str:
    # WAFv2 CLOUDFRONT-scope web ACLs are global but must be managed through the us-east-1
    # endpoint (any other region answers WAFInvalidParameterException "The scope is not
    # valid."). Pinned through ctx.client(..., region=) rather than aborting on ctx.region, so
    # the same code path runs against every target -- an emulator keeps its shared endpoint.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-cf-block-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Block": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]
    arn = summary["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, name, web_acl_id))
    return arn


def _delete_web_acl(ctx, name: str, web_acl_id: str) -> None:
    waf = ctx.client("wafv2", region="us-east-1")
    lock_token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _http_get(url: str, route: dict, timeout: float = 10.0, verify=True):
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral-check", **route})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _poll_http_get(url: str, route: dict, expect_status: int, timeout_s: float = 60.0, interval_s: float = 5.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        last = _http_get(url, route, verify=verify)
        if last[0] == expect_status:
            return last
        time.sleep(interval_s)
    return last


def _poll_until_status(url: str, route: dict, expect_status: int, timeout_s: float, interval_s: float = 5.0, verify=True) -> bool:
    status, _ = _poll_http_get(url, route, expect_status, timeout_s=timeout_s, interval_s=interval_s, verify=verify)
    return status == expect_status


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
