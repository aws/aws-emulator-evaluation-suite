"""cf-origin-access-control-blocks-direct-s3-access-rejected."""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET

import requests

from behavioral_harness import tags

CHECK = "cf-origin-access-control-blocks-direct-s3-access-rejected"
GROUP = 'origin-access-control'
SERVICES = ['cloudfront', 's3']

#: CloudFront's control plane is global and lives ONLY in us-east-1. This is a combo suite, so the
#: harness resolves the sts endpoint and ctx.region is the check's region — the S3 bucket belongs there
#: and the cloudfront client must be pinned here. The two clients are not interchangeable.
CLOUDFRONT_REGION = "us-east-1"

#: Prefixes a failure of the CloudFront data-plane read, so it reads as an endpoint failure rather
#: than a connection error.
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

    Create -> Deployed and disable -> Deployed each take a few minutes on AWS; 900s leaves ample
    headroom.
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

    DeleteDistribution issued immediately after the disabling UpdateDistribution is refused with
    ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than defensive.
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
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An OAC-scoped bucket refuses an anonymous S3 GET while serving the same object through CloudFront.

    Only the caller differs: CloudFront and the caller's own GetObject read the exact bytes, so the
    anonymous 403 is about who asks, never about the object.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfoac-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })

    key = "asset.txt"
    body = b"sim2real-oac-protected-object"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfoac-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    # The S3 REST endpoint, in the BUCKET's region — not the cloudfront client's region. A bucket in
    # another region behind a distribution in us-east-1 is the normal arrangement, and naming the
    # wrong region here yields a permanent redirect the edge reports as a 301.
    bucket_host = f"{bucket}.s3.{ctx.region}.amazonaws.com"

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfoac-cr-"),
        "Comment": "sim2real OAC locks the origin",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": bucket_host,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # managed CachingDisabled
        },
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    _wait_distribution_deployed(cf, dist_id)

    # POSITIVE CONTROL 1 — the object through the edge. Polled, because it is also what proves the
    # OAC signing and the bucket policy took effect; only then is the anonymous 403 attributable.
    session = requests.Session()
    cf_url, cf_headers = ctx.endpoint_route(f"{domain}/{key}")
    session.headers.update(cf_headers)

    def cf_probe():
        try:
            return session.get(cf_url, timeout=15, verify=ctx.http_verify)
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            return exc

    try:
        through_cf = _poll_until(
            cf_probe,
            lambda r: isinstance(r, requests.Response) and r.status_code == 200,
            timeout_s=180, interval_s=5,
            description=f"200 through the distribution at {cf_url}",
        )
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc

    assert through_cf.status_code == 200, (
        f"CloudFront could not read the OAC-protected origin: {through_cf.status_code!r} / "
        f"{through_cf.text[:200]!r}"
    )
    assert through_cf.content == body, (
        f"CloudFront served the wrong bytes: {through_cf.content!r}"
    )

    # POSITIVE CONTROL 2 — the same object with the caller's own credentials, straight at S3. Proves the
    # object exists and is readable, so the anonymous 403 below cannot be a missing object.
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body, (
        "the caller-credential GetObject did not return the object that was uploaded"
    )

    # THE NEGATIVE — a session with no credentials whatsoever. Plain requests, never botocore, so
    # nothing can sign it by accident.
    direct = requests.Session()
    direct.trust_env = False  # no proxy or netrc from the environment may add credentials
    # Path-style, so the request names the bucket on any target's S3 host.
    s3_url, s3_headers = ctx.endpoint_route(f"{ctx.client('s3').meta.endpoint_url}/{bucket}/{key}")
    resp = direct.get(s3_url, headers=s3_headers, timeout=20, verify=ctx.http_verify)

    assert resp.status_code == 403, (
        f"an anonymous GET straight at the OAC-locked S3 origin was not refused: "
        f"{resp.status_code!r} / {resp.text[:200]!r}"
    )
    s3_error = ET.fromstring(resp.text)
    s3_code = s3_error.findtext("Code")
    s3_message = s3_error.findtext("Message")
    assert (s3_code, s3_message) == ("AccessDenied", "Access Denied"), (
        f"expected AccessDenied 'Access Denied' from S3, got {s3_code!r} {s3_message!r} / "
        f"{resp.text[:200]!r}"
    )
    assert body not in resp.content, (
        f"the S3 403 body leaked the object's bytes: {resp.content[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
