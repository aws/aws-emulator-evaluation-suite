"""cf-response-headers-policy-adds-and-overrides-headers-at-edge."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cf-response-headers-policy-adds-and-overrides-headers-at-edge"
GROUP = 'policies'
SERVICES = ['cloudfront']

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each typically take a few minutes; 900 s leaves a
    wide margin.
    """
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete.

    DeleteDistribution issued immediately after the disabling UpdateDistribution is
    refused with ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than
    defensive. A distribution left enabled cannot be found by name later,
    because its id is server-minted.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _fetch(session, url, *, timeout_s=180.0, interval_s=5.0):
    """GET ``url`` until it answers 200; DATAPLANE_MARKER on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=15)
            return last
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            last = exc
            return None

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A response-headers policy adds its headers at the edge, and Override decides whether the
    policy's or the S3 origin's value of the same header reaches the viewer.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfrhp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )

    key = "obj.txt"
    body = b"sim2real-response-headers-object"
    # S3 returns each Metadata entry as `x-amz-meta-<name>`, so the ORIGIN owns a value for both
    # the conflict header and the passthrough header.
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain",
                  Metadata={"conflict": "from-origin", "passthrough": "from-origin"})

    policy_id = cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cfrhp-p-"),
        "Comment": "sim2real response headers add + override",
        "SecurityHeadersConfig": {
            "StrictTransportSecurity": {"Override": True, "AccessControlMaxAgeSec": 31536000},
        },
        "CustomHeadersConfig": {"Quantity": 3, "Items": [
            # The origin never sends this one: pure addition.
            {"Header": "x-fidelity", "Value": "edge", "Override": True},
            # The origin DOES send this one; Override=true must replace it.
            {"Header": "x-amz-meta-conflict", "Value": "edge", "Override": True},
            # The origin DOES send this one; Override=false must leave it alone.
            {"Header": "x-amz-meta-passthrough", "Value": "edge", "Override": False},
        ]},
    })["ResponseHeadersPolicy"]["Id"]

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfrhp-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]

    # CachingDisabled, so every request reaches the origin and the header arbitration is observed
    # on a fresh origin response rather than on a cached copy.
    MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfrhp-cr-"),
        "Comment": "sim2real response headers add + override",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            "ResponseHeadersPolicyId": policy_id,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    domain = dist["DomainName"]
    cf.tag_resource(
        Resource=dist["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )
    # Registered slowest-first so LIFO order runs the cheap, fast deletes (bucket, policy, OAC)
    # BEFORE the distribution's disable-then-wait-then-delete, which alone routinely nears the
    # 60s cleanup budget (see _wait_distribution_deployed) — so those three must not be queued
    # behind it and left stranded if the budget is exceeded.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_response_headers_policy,
                                             cf.delete_response_headers_policy, policy_id))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    _wait_distribution_deployed(cf, dist_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    resp = _fetch(session, f"{edge}/{key}")
    headers = resp.headers

    assert headers.get("x-fidelity") == "edge", (
        f"the policy's custom header never reached the viewer: {headers.get('x-fidelity')!r} "
        f"(all headers: {dict(headers)!r})"
    )
    assert headers.get("x-amz-meta-conflict") == "edge", (
        f"Override=true did not replace the origin's value: "
        f"{headers.get('x-amz-meta-conflict')!r} (origin sent 'from-origin')"
    )
    assert headers.get("x-amz-meta-passthrough") == "from-origin", (
        f"Override=false wrongly replaced the origin's value: "
        f"{headers.get('x-amz-meta-passthrough')!r} (origin sent 'from-origin')"
    )
    assert "max-age=31536000" in (headers.get("strict-transport-security") or ""), (
        f"the SecurityHeadersConfig HSTS header was not applied: "
        f"{headers.get('strict-transport-security')!r}"
    )
    assert resp.content == body, (
        f"the object itself was not served intact: {resp.content!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
