"""signed-cookies-key-group-admits-private-prefix-rejects-outside-resource."""
from __future__ import annotations

import base64
import json
import time
import urllib.parse
import xml.etree.ElementTree as ET

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "signed-cookies-key-group-admits-private-prefix-rejects-outside-resource"
GROUP = "security"
SERVICES = ["cloudfront", "s3"]

#: The AWS-managed "CachingDisabled" cache policy: signed content must never be served from a
#: shared cache entry to a viewer that was never authorized for it.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_TAGS = [{"Key": "sim2real", "Value": "behavioral"}]


def _poll(probe, done, *, timeout_s, interval_s=5.0, what="condition"):
    """Retry ``probe`` until ``done`` holds; raises (never returns stale) past ``timeout_s``."""
    deadline = time.monotonic() + timeout_s
    seen = None
    while time.monotonic() < deadline:
        seen = probe()
        if done(seen):
            return seen
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last observed {seen!r}")


def _wait_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=15.0) -> str:
    """Poll GetDistribution to Status == 'Deployed'; return the ETag read at that moment."""
    state: dict[str, str] = {}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        state["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
          what=f"distribution {dist_id} reaching Deployed")
    return state["etag"]


def _disable_then_delete(cf, dist_id) -> None:
    """Disable the distribution, wait for that to deploy, then delete it."""
    current = cf.get_distribution_config(Id=dist_id)
    etag = current["ETag"]
    body = current["DistributionConfig"]
    if body.get("Enabled"):
        body["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=body)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_by_etag(get_call, delete_call, resource_id) -> None:
    delete_call(Id=resource_id, IfMatch=get_call(Id=resource_id)["ETag"])


def _create_private_bucket(ctx, s3, bucket) -> None:
    """A bucket with its teardown registered on the next statement, then every public-access block."""
    # us-east-1 is the one region whose CreateBucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})


def _drain_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if errors:
                raise AssertionError(f"DeleteObjects left {len(errors)} object(s) in {bucket!r}: "
                                     f"{errors[:3]!r}")
    s3.delete_bucket(Bucket=bucket)


def _grant_distribution_read(s3, bucket, distribution_arn) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontDistributionRead",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{distribution_arn.split(':')[1]}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
        }],
    }))


def _cf_safe_b64(data: bytes) -> str:
    """CloudFront's URL/cookie-safe base64: '+'->'-', '/'->'~', '='->'_' (not RFC 4648 urlsafe)."""
    return base64.b64encode(data).decode().translate(str.maketrans("+/=", "-~_"))


def _policy_document(resource_url: str, expires_epoch: int) -> bytes:
    return json.dumps({
        "Statement": [{
            "Resource": resource_url,
            "Condition": {"DateLessThan": {"AWS:EpochTime": expires_epoch}},
        }],
    }, separators=(",", ":")).encode()


def _cookie_headers(resource_url: str, expires_epoch: int, private_key, key_pair_id: str) -> dict[str, str]:
    """The three Set-Cookie name/value pairs a viewer presents for a custom-policy signed cookie."""
    policy_bytes = _policy_document(resource_url, expires_epoch)
    signature = private_key.sign(policy_bytes, padding.PKCS1v15(), hashes.SHA1())
    return {
        "CloudFront-Policy": _cf_safe_b64(policy_bytes),
        "CloudFront-Signature": _cf_safe_b64(signature),
        "CloudFront-Key-Pair-Id": key_pair_id,
    }


#: The edge error document for a request with no signed credential at all.
_MISSING_KEY = ("MissingKey", "Missing Key-Pair-Id query parameter or cookie value")
#: The edge error document for a signed cookie CloudFront will not honor: an expired policy, or
#: one whose Resource does not cover the requested URL.
_ACCESS_DENIED = ("AccessDenied", "Access denied")


def _edge_error(response_text: str) -> tuple[str, str]:
    """The edge error document's (Code, Message), or ("", "") when the body is not that document."""
    try:
        doc = ET.fromstring(response_text)
    except ET.ParseError:
        return "", ""
    return doc.findtext("Code") or "", doc.findtext("Message") or ""


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A signed-cookie custom policy admits every object its wildcard Resource covers and is
    refused, by the same cookies, on a path outside that Resource, with no credential or an
    expired policy refused too.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-custom-policy.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfpriv-").lower()
    _create_private_bucket(ctx, s3, bucket)

    key_a = "private/doc-a.txt"
    key_b = "private/doc-b.txt"
    key_outside = "welcome.txt"
    body_a = b"sim2real-private-prefix-object-a"
    body_b = b"sim2real-private-prefix-object-b"
    body_outside = b"sim2real-outside-prefix-object"
    s3.put_object(Bucket=bucket, Key=key_a, Body=body_a, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=key_b, Body=body_b, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=key_outside, Body=body_outside, ContentType="text/plain")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    public_key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfpriv-pk-"),
        "Name": ctx.unique_name("sim2real-behav-cfpriv-pk-"),
        "EncodedKey": public_pem,
        "Comment": "verifies signed cookies for a path-scoped cache behavior",
    })["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_public_key, cf.delete_public_key, public_key_id))

    key_group_id = cf.create_key_group(KeyGroupConfig={
        "Name": ctx.unique_name("sim2real-behav-cfpriv-kg-"),
        "Items": [public_key_id],
        "Comment": "trusted for the private-prefix cache behavior",
    })["KeyGroup"]["Id"]
    # Registered after the public key's cleanup so LIFO deletes the group BEFORE the key: a
    # public key still referenced by a key group cannot be deleted.
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_key_group, cf.delete_key_group, key_group_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfpriv-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_origin_access_control,
                                           cf.delete_origin_access_control, oac_id))

    trusted_group = {"Enabled": True, "Quantity": 1, "Items": [key_group_id]}
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfpriv-cr-"),
        "Comment": "every path requires a trusted signed cookie, with one cache behavior scoped to a prefix",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            # https-only: a signed cookie must never cross the wire unencrypted.
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            "TrustedKeyGroups": trusted_group,
        },
        "CacheBehaviors": {"Quantity": 1, "Items": [{
            "PathPattern": "private/*",
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            "TrustedKeyGroups": trusted_group,
        }]},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_then_delete(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAGS})

    _grant_distribution_read(s3, bucket, dist["ARN"])
    _wait_deployed(cf, dist_id)

    session = requests.Session()
    edge, route_headers = ctx.endpoint_route(domain)
    session.headers.update(route_headers)
    url_a = f"{edge}/{key_a}"
    url_b = f"{edge}/{key_b}"
    url_outside = f"{edge}/{key_outside}"
    scheme = urllib.parse.urlsplit(edge).scheme
    # One wildcard Resource for the whole "private/*" prefix — the custom policy's defining
    # capability over a canned policy, which can only name one exact URL.
    private_prefix_resource = f"{scheme}://{domain}/private/*"

    now = int(time.time())
    valid_cookies = _cookie_headers(private_prefix_resource, now + 900, private_key, public_key_id)
    expired_cookies = _cookie_headers(private_prefix_resource, now - 600, private_key, public_key_id)

    # BEAT 1 — positive control, polled because the distribution has only just deployed.
    def probe_admitted():
        try:
            return session.get(url_a, cookies=valid_cookies, timeout=15, verify=ctx.http_verify)
        except requests.RequestException as exc:  # transport only
            return exc

    admitted = _poll(
        probe_admitted,
        lambda r: isinstance(r, requests.Response) and r.status_code == 200,
        timeout_s=180.0, interval_s=5.0, what="200 for the correctly signed cookie set",
    )
    assert admitted.content == body_a, (
        f"expected {body_a!r} for the admitted request, got {admitted.content[:120]!r}"
    )

    # BEAT 2 — the SAME cookie set, over the wildcard Resource, also reaches the second object.
    second = session.get(url_b, cookies=valid_cookies, timeout=15, verify=ctx.http_verify)
    assert second.status_code == 200, (
        f"a policy with Resource={private_prefix_resource!r} covers every object under the "
        f"prefix: expected 200 for {key_b!r}, got {second.status_code} / {second.text[:200]!r}"
    )
    assert second.content == body_b, (
        f"expected {body_b!r} for {key_b!r}, got {second.content[:120]!r}"
    )

    # BEAT 3 — break exactly one thing: no cookies at all.
    missing = session.get(url_a, timeout=15, verify=ctx.http_verify)
    assert missing.status_code == 403, (
        f"a request carrying no signed cookie must be refused: expected 403, got "
        f"{missing.status_code} / {missing.text[:200]!r}"
    )
    missing_error = _edge_error(missing.text)
    assert missing_error == _MISSING_KEY, (
        f"a request with no signed credential must be refused with {_MISSING_KEY!r}, got "
        f"{missing_error!r} / {missing.text[:200]!r}"
    )

    # BEAT 4 — break exactly one OTHER thing: a validly signed but EXPIRED policy.
    stale = session.get(url_a, cookies=expired_cookies, timeout=15, verify=ctx.http_verify)
    assert stale.status_code == 403, (
        f"an expired custom policy must be refused: expected 403, got {stale.status_code} / "
        f"{stale.text[:200]!r}"
    )
    stale_error = _edge_error(stale.text)
    assert stale_error == _ACCESS_DENIED, (
        f"an expired custom policy must be refused with {_ACCESS_DENIED!r}, got {stale_error!r} "
        f"/ {stale.text[:200]!r}"
    )

    # BEAT 5 — the SAME valid cookie set, presented to a path its Resource does not cover.
    outside = session.get(url_outside, cookies=valid_cookies, timeout=15, verify=ctx.http_verify)
    assert outside.status_code == 403, (
        f"a policy whose Resource is {private_prefix_resource!r} must not admit a request "
        f"outside that prefix: expected 403 for {key_outside!r}, got {outside.status_code} / "
        f"{outside.text[:200]!r}"
    )
    outside_error = _edge_error(outside.text)
    assert outside_error == _ACCESS_DENIED, (
        f"a request outside the policy's Resource must be refused with {_ACCESS_DENIED!r}, got "
        f"{outside_error!r} / {outside.text[:200]!r}"
    )

    # BEAT 6 — none of the three refusals leaked protected bytes.
    for label, resp in (("missing-cookie", missing), ("expired-policy", stale),
                        ("outside-resource", outside)):
        assert (body_a not in resp.content and body_b not in resp.content
                and body_outside not in resp.content), (
            f"the {label} refusal body leaked protected bytes: {resp.content[:200]!r}"
        )

    # BEAT 7 — restore: the identical admitted call still works after the three refusals.
    restored = session.get(url_a, cookies=valid_cookies, timeout=15, verify=ctx.http_verify)
    assert restored.status_code == 200, (
        f"the original cookie set must still be admitted: expected 200, got "
        f"{restored.status_code} / {restored.text[:200]!r}"
    )
    assert restored.content == body_a, (
        f"expected {body_a!r} on the restore leg, got {restored.content[:120]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
