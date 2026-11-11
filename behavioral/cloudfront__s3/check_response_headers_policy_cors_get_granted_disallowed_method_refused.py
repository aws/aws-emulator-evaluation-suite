"""response-headers-policy-cors-get-granted-disallowed-method-refused."""

from __future__ import annotations

import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "response-headers-policy-cors-get-granted-disallowed-method-refused"
GROUP = "cors"
SERVICES = ["cloudfront", "s3"]

#: CloudFront's control plane is global and answers only in us-east-1.
CLOUDFRONT_REGION = "us-east-1"
#: The longest wait any step takes (a distribution reaching Deployed). Declared > 300 s so the
#: derived per-check and teardown budgets lift; it is a ceiling to fail at, never a latency claim.
_DEPLOYED_DEADLINE_S = 900
#: The managed CachingDisabled cache policy, so each viewer request reaches the origin.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
ALLOWED = "https://app.example.com"
FOREIGN = "https://other.example.net"
KEY = "app/config.json"
#: CloudFront's own refusal of a method outside the cache behavior's AllowedMethods.
METHOD_REFUSED = ("This distribution is not configured to allow the HTTP request method that was "
                  "used for this request. The distribution supports only cachable requests.")
BODY = json.dumps({"feature": "sim2real-browser-cors"}).encode()


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cross-origin GET through a distribution with a CORS response headers policy returns the
    OAC-fetched object with Allow-Origin (none for a foreign origin); a DELETE outside the cache
    behavior's AllowedMethods is refused 403 by CloudFront itself and never reaches the origin.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-response-headers-policies.html
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")
    bucket = _private_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=KEY, Body=BODY, ContentType="application/json")
    oac_id = _create_oac(ctx, cf, bucket)
    policy_id = _create_cors_policy(ctx, cf)
    dist = _create_distribution(ctx, cf, _config(bucket, f"{bucket}.s3.{ctx.region}.amazonaws.com",
                                                 oac_id, policy_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{_partition(ctx)}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))
    _wait_deployed(cf, dist["Id"])
    url, route = ctx.endpoint_route(f"{dist['DomainName']}/{KEY}")

    # Positive control: the cross-origin GET from the allowed origin, polled while the new
    # domain propagates to the edge.
    resp = _poll(ctx, lambda: _get(ctx, url, {**route, "Origin": ALLOWED}), 200,
                 description=f"GET {url} from {ALLOWED}")
    assert resp.content == BODY, f"the edge must serve the object's bytes, got {resp.content[:200]!r}"
    assert _cors(resp) == {"access-control-allow-origin": ALLOWED}, (
        f"the allowed GET must carry exactly the policy's Allow-Origin, got {_cors(resp)!r}"
    )

    # Negative: the same GET from a foreign origin is served with no grant.
    resp = _get(ctx, url, {**route, "Origin": FOREIGN})
    assert (resp.status_code, resp.content) == (200, BODY), (
        f"CORS is not enforced server side: the foreign GET is still served, got "
        f"{(resp.status_code, resp.content[:200])!r}"
    )
    assert _cors(resp) == {}, f"a foreign-origin GET must carry no CORS header, got {_cors(resp)!r}"

    # Negative: a DELETE from the allowed origin is a method the behavior does not allow.
    resp = requests.delete(url, headers={**route, "Origin": ALLOWED}, timeout=20,
                           verify=ctx.http_verify)
    assert (resp.status_code, _refusal_message(resp.text)) == (403, METHOD_REFUSED), (
        f"a disallowed method: want 403 {METHOD_REFUSED!r}, got {(resp.status_code, resp.text)!r}"
    )
    assert resp.headers.get("x-cache") == "Error from cloudfront", (
        f"the refusal must come from CloudFront, not the origin: {dict(resp.headers)!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=KEY)["Body"].read() == BODY, (
        "the refused DELETE must leave the object in place"
    )


def _refusal_message(html: str) -> str:
    """The message line of CloudFront's error page: the first line after its first rule."""
    _, sep, rest = html.partition('<HR noshade size="1px">\n')
    return rest.split("\n", 1)[0] if sep else f"<no CloudFront error page in {html[:200]!r}>"


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN."""
    return ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]


def _get(ctx, url: str, headers: dict):
    """One GET through the edge; a connection error while the edge propagates is returned."""
    try:
        return requests.get(url, headers=headers, timeout=20, verify=ctx.http_verify)
    except requests.RequestException as exc:
        return exc


def _poll(ctx, probe, want: int, *, description: str, timeout_s: float = 300.0):
    """Re-issue probe() until it answers `want`, within the check's time left; fail naming the last
    answer."""
    left = ctx.time_left()
    timeout_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 15.0))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if isinstance(last, requests.Response) and last.status_code == want:
            return last
        time.sleep(5)
    detail = last if not isinstance(last, requests.Response) else (last.status_code, last.text[:200])
    raise AssertionError(f"{description} not answered {want} within {timeout_s}s; last {detail!r}")


def _cors(resp) -> dict:
    return {k.lower(): v for k, v in resp.headers.items()
            if k.lower().startswith("access-control-")}


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    """Poll probe() until predicate(result) holds; return it, or fail naming the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id: str) -> str:
    """Poll GetDistribution to Status=Deployed and return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S,
                description=f"distribution {dist_id} reaching Deployed")
    return holder["etag"]


def _retire_distribution(cf, dist_id: str) -> None:
    """Disable if enabled, wait for Deployed, delete. Raises on anything but not-found."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_oac(ctx, cf, name: str) -> str:
    """An S3 origin access control that signs every request with SigV4, with its cleanup."""
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": name,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]

    def _delete() -> None:
        try:
            cf.delete_origin_access_control(
                Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_delete)
    return oac_id


def _create_cors_policy(ctx, cf) -> str:
    """A response headers policy granting CORS to ALLOWED only, overriding any origin CORS."""
    policy_id = cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cors-"),
        "CorsConfig": {
            "AccessControlAllowOrigins": {"Quantity": 1, "Items": [ALLOWED]},
            "AccessControlAllowHeaders": {"Quantity": 1, "Items": ["content-type"]},
            "AccessControlAllowMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            "AccessControlAllowCredentials": False,
            "OriginOverride": True,
        },
    })["ResponseHeadersPolicy"]["Id"]

    def _delete() -> None:
        try:
            etag = cf.get_response_headers_policy(Id=policy_id)["ETag"]
            cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
                raise

    ctx.on_cleanup(_delete)
    return policy_id


def _config(caller_ref: str, origin_host: str, oac_id: str, policy_id: str) -> dict:
    return {
        "CallerReference": caller_ref,
        "Comment": "sim2real browser cors",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginAccessControlId": oac_id,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "S3Origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": CACHING_DISABLED,
            "ResponseHeadersPolicyId": policy_id,
        },
    }


def _create_distribution(ctx, cf, config: dict) -> dict:
    """CreateDistribution with its retirement registered on the very next statement."""
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist["Id"]))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]})
    return dist


def _private_bucket(ctx, s3) -> str:
    """A bucket with all four public-access blocks on, with its emptying teardown registered first."""
    bucket = ctx.unique_name("sim2real-xsvc-cors-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object, then the bucket. Raises on anything but not-found."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
