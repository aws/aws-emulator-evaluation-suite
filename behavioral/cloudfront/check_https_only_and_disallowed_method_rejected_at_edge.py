"""https-only-and-disallowed-method-rejected-at-edge."""
from __future__ import annotations

import json
import os
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "https-only-and-disallowed-method-rejected-at-edge"
GROUP = "viewer-protocol-enforcement"
SERVICES = ["cloudfront"]

#: CloudFront's control plane is global and lives only in us-east-1; the origin bucket is in
#: ctx.region.
CLOUDFRONT_REGION = "us-east-1"

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed cache policy


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The edge enforces viewer protocol policy and allowed methods itself: redirect-to-https answers
    HTTP with a 301, https-only with a 403 and no bytes, a GET/HEAD-only behavior refuses POST with
    a 403, and each refusal is bracketed by a 200 on the same object.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfvpp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    open_key, secure_key = "open/page.txt", "secure/page.txt"
    open_body = b"sim2real-open:" + os.urandom(512)
    secure_body = b"sim2real-secure:" + os.urandom(512)
    s3.put_object(Bucket=bucket, Key=open_key, Body=open_body, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=secure_key, Body=secure_body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfvpp-oac-"),
        "Description": "sim2real https-only-and-disallowed-method-rejected-at-edge",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    origin_id = "s3origin"
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfvpp-cr-"),
        "Comment": "sim2real viewer protocol + allowed methods enforcement",
        "Enabled": True,
        "PriceClass": "PriceClass_100",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": origin_id,
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": CACHING_DISABLED,
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
        },
        "CacheBehaviors": {"Quantity": 1, "Items": [{
            "PathPattern": "secure/*",
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": CACHING_DISABLED,
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
        }]},
    })["Distribution"]
    dist_id, domain = dist["Id"], dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontOACRead",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    _wait_distribution_deployed(cf, dist_id)

    http = requests.Session()
    http.trust_env = False
    http.verify = ctx.http_verify
    plain, plain_route = ctx.endpoint_route(f"http://{domain}")
    # tls: the viewer protocol policy is the subject, so both viewer schemes are named
    secure, secure_route = ctx.endpoint_route(f"https://{domain}")
    routes = ((secure, secure_route), (plain, plain_route))

    def get(url, method="GET", **kw):
        headers = next(route for base, route in routes if url.startswith(f"{base}/"))
        try:
            return http.request(method, url, headers=headers, timeout=20, allow_redirects=False, **kw)
        except requests.RequestException as exc:  # transient during edge propagation; recorded
            return exc

    # POSITIVE CONTROL: both objects over HTTPS, polled because it also proves the OAC + policy.
    try:
        # tls: the viewer protocol policy is the subject, so the viewer scheme is named
        ok_open = _poll_until(lambda: get(f"{secure}/{open_key}"),
                              lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                              timeout_s=300, interval_s=10,
                              description=f"HTTPS 200 for https://{domain}/{open_key}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    assert ok_open.content == open_body, f"edge served wrong bytes for {open_key}: {ok_open.content[:64]!r}"
    # tls: the viewer protocol policy is the subject, so the viewer scheme is named
    ok_secure = _poll_until(lambda: get(f"{secure}/{secure_key}"),
                            lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                            timeout_s=120, interval_s=5,
                            description=f"HTTPS 200 for https://{domain}/{secure_key}")
    assert ok_secure.content == secure_body, (
        f"edge served wrong bytes for {secure_key}: {ok_secure.content[:64]!r}"
    )

    # redirect-to-https: plain HTTP is answered with a 301 to the same path on https.
    r = get(f"{plain}/{open_key}")
    assert isinstance(r, requests.Response), f"plain HTTP GET to {domain} failed to connect: {r!r}"
    assert r.status_code == 301, (
        f"redirect-to-https answered plain HTTP with {r.status_code!r}, expected 301; "
        f"headers {dict(r.headers)!r}"
    )
    # tls: the viewer protocol policy is the subject, so the viewer scheme is named
    assert r.headers.get("Location") == f"https://{domain}/{open_key}", (
        f"301 Location is {r.headers.get('Location')!r}, expected https://{domain}/{open_key}"
    )
    assert open_body not in r.content, "the 301 response carried the object's bytes"

    # NEGATIVE 1 -- https-only over plain HTTP: refused at the edge, no redirect, no bytes.
    r = get(f"{plain}/{secure_key}")
    assert isinstance(r, requests.Response), f"plain HTTP GET to {domain} failed to connect: {r!r}"
    assert r.status_code == 403, (
        f"https-only behavior answered plain HTTP with {r.status_code!r}, expected 403; "
        f"headers {dict(r.headers)!r}"
    )
    assert r.headers.get("x-cache") == "Error from cloudfront", (
        f"the 403 was not generated by the edge: x-cache={r.headers.get('x-cache')!r}"
    )
    assert "Location" not in r.headers, f"https-only must not redirect: {r.headers.get('Location')!r}"
    assert secure_body not in r.content, "the https-only 403 leaked the object's bytes"

    # NEGATIVE 2 -- POST against a GET/HEAD-only behavior over HTTPS: refused at the edge.
    # tls: the viewer protocol policy is the subject, so the viewer scheme is named
    r = get(f"{secure}/{open_key}", method="POST", data=b"sim2real-post-body")
    assert isinstance(r, requests.Response), f"HTTPS POST to {domain} failed to connect: {r!r}"
    assert r.status_code == 403, (
        f"a GET/HEAD-only behavior answered POST with {r.status_code!r}, expected 403"
    )
    assert r.headers.get("x-cache") == "Error from cloudfront", (
        f"the POST 403 was not generated by the edge: x-cache={r.headers.get('x-cache')!r}"
    )
    assert open_body not in r.content, "the POST 403 leaked the object's bytes"

    # The refusals changed nothing: the same URL still serves the object over HTTPS GET.
    # tls: the viewer protocol policy is the subject, so the viewer scheme is named
    again = get(f"{secure}/{open_key}")
    assert isinstance(again, requests.Response) and again.status_code == 200, (
        f"HTTPS GET after the refusals returned {again!r}"
    )
    assert again.content == open_body, "the object served after the refusals differs from the upload"

    # TEARDOWN IN THE BODY, deliberately. The runner bounds the whole cleanup chain at 60 s
    # (simparity DEFAULT_CLEANUP_TIMEOUT_S) and a distribution needs disable -> Deployed -> delete,
    # measured at ~3 min, so a cleanup-only teardown is cut off mid-wait and leaks the distribution,
    # its OAC and the bucket. The on_cleanup registrations above stay as the failure-path net and
    # tolerate a resource that is already gone.
    _disable_and_delete_distribution(cf, dist_id)
    _delete_with_etag(cf.get_origin_access_control, cf.delete_origin_access_control, oac_id)
    _empty_and_delete_bucket(s3, bucket)


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete (DeleteDistribution refuses an enabled
    or not-yet-Deployed distribution with DistributionNotDisabled). Already gone is done."""
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    try:
        etag = get_fn(Id=resource_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"].startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
