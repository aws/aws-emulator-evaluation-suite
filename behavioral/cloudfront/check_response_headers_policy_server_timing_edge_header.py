"""response-headers-policy-server-timing-edge-header."""
from __future__ import annotations

import json
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "response-headers-policy-server-timing-edge-header"
GROUP = "response-headers-policies"
SERVICES = ["cloudfront", "s3"]

#: AWS-managed cache policy that disables caching, so every GET reaches the origin.
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
#: Every metric name the Server-Timing header documentation lists.
_METRIC_NAMES = frozenset(
    {
        "cdn-cache-hit",
        "cdn-cache-refresh",
        "cdn-cache-miss",
        "cdn-pop",
        "cdn-rid",
        "cdn-hit-layer",
        "cdn-upstream-layer",
        "cdn-upstream-dns",
        "cdn-upstream-connect",
        "cdn-upstream-fbl",
        "cdn-downstream-fbl",
    }
)
#: Metrics every documented example carries, whatever the cache outcome.
_ALWAYS_PRESENT = frozenset({"cdn-pop", "cdn-rid"})
_DEPLOY_DEADLINE_S = 1500.0
_HEADER_DEADLINE_S = 600.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _ssl_context(verify) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    if verify is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _get(url: str, verify) -> tuple[int, dict]:
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context(verify)))
    with opener.open(urllib.request.Request(url, method="GET"), timeout=30.0) as resp:
        return resp.status, dict(resp.headers)


def _wait_deployed(cf, dist_id: str, *, deadline_s: float = _DEPLOY_DEADLINE_S) -> None:
    deadline = time.monotonic() + deadline_s
    while True:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"distribution {dist_id} still {status!r} after {deadline_s}s")
        time.sleep(3.0)


def _poll_server_timing(url: str, verify, *, present: bool, deadline_s: float = _HEADER_DEADLINE_S):
    """GET ``url`` until ``"Server-Timing" in headers`` matches ``present``, or raise with it."""
    deadline = time.monotonic() + deadline_s
    headers: dict = {}
    while True:
        status, headers = _get(url, verify)
        assert status == 200, f"GET {url} returned {status}, expected 200"
        if ("Server-Timing" in headers) == present:
            return headers
        if time.monotonic() > deadline:
            want = "present" if present else "absent"
            raise AssertionError(
                f"Server-Timing never became {want} within {deadline_s}s; last headers {headers!r}"
            )
        time.sleep(3.0)


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
    "dp:endpoint", "plane:data", "plane:control",
)
def run(ctx) -> None:
    """A response headers policy with Server-Timing enabled makes CloudFront add that header,
    carrying documented metric names, to a viewer response; detaching the policy removes it.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-response-headers-policies.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cf-origin-")
    bucket_region = s3.meta.region_name
    if bucket_region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": bucket_region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))

    key = "index.html"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real server-timing check", ContentType="text/html")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))

    oac_name = ctx.unique_name("sim2real-behav-cf-oac-")
    oac_created = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": oac_name,
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = oac_created["OriginAccessControl"]["Id"]
    oac_etag = oac_created["ETag"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_origin_access_control(Id=oac_id, IfMatch=oac_etag), "NoSuchOriginAccessControl"
    ))

    policy_name = ctx.unique_name("sim2real-behav-cf-rhp-")
    rhp_created = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Name": policy_name,
            "ServerTimingHeadersConfig": {"Enabled": True, "SamplingRate": 100.0},
        }
    )
    policy_id = rhp_created["ResponseHeadersPolicy"]["Id"]
    policy_etag = rhp_created["ETag"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_response_headers_policy(Id=policy_id, IfMatch=policy_etag),
        "NoSuchResponseHeadersPolicy",
    ))

    origin_id = "sim2real-behav-cf-origin"
    dist_name = ctx.unique_name("sim2real-behav-cf-dist-")
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": dist_name,
                "Comment": dist_name,
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": origin_id,
                            "DomainName": f"{bucket}.s3.{bucket_region}.amazonaws.com",
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                            "OriginAccessControlId": oac_id,
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": origin_id,
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                    "ResponseHeadersPolicyId": policy_id,
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": dist_name}]},
        }
    )["Distribution"]
    dist_id = created["Id"]
    dist_arn = created["ARN"]
    domain_name = created["DomainName"]

    def _delete_distribution() -> None:
        cfg = cf.get_distribution_config(Id=dist_id)
        body, etag = cfg["DistributionConfig"], cfg["ETag"]
        if body["Enabled"]:
            body["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=body, IfMatch=etag)
            _wait_deployed(cf, dist_id)
            etag = cf.get_distribution_config(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)

    ctx.on_cleanup(_teardown(_delete_distribution, "NoSuchDistribution"))

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontServicePrincipalReadOnly",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"aws:SourceArn": dist_arn}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    _wait_deployed(cf, dist_id)

    url = f"{ctx.endpoint_url(domain_name)}/{key}"
    attached = _poll_server_timing(url, ctx.http_verify, present=True)
    server_timing = attached["Server-Timing"]
    names = {metric.strip().split(";", 1)[0] for metric in server_timing.split(",")}
    assert names <= _METRIC_NAMES, (
        f"Server-Timing named {sorted(names - _METRIC_NAMES)}, outside the documented metrics: "
        f"{server_timing!r}"
    )
    assert _ALWAYS_PRESENT <= names, (
        f"Server-Timing is missing {sorted(_ALWAYS_PRESENT - names)}, present in every documented "
        f"example: {server_timing!r}"
    )

    cfg = cf.get_distribution_config(Id=dist_id)
    body, etag = cfg["DistributionConfig"], cfg["ETag"]
    body["DefaultCacheBehavior"].pop("ResponseHeadersPolicyId", None)
    cf.update_distribution(Id=dist_id, DistributionConfig=body, IfMatch=etag)
    _wait_deployed(cf, dist_id)

    detached = _poll_server_timing(url, ctx.http_verify, present=False)
    assert "Server-Timing" not in detached, (
        f"Server-Timing is still present after detaching the policy: {detached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
