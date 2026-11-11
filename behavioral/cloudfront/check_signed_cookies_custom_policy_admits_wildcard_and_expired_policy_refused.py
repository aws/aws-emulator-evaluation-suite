"""signed-cookies-custom-policy-admits-wildcard-and-expired-policy-refused."""
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

CHECK = "signed-cookies-custom-policy-admits-wildcard-and-expired-policy-refused"
GROUP = "security"
SERVICES = ["cloudfront"]

#: Prefix that classifies a failure as an unimplemented data-plane endpoint.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: an edge cache entry could serve a refused request from an admitted one.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
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


def _create_bucket(ctx, s3, bucket) -> None:
    # us-east-1 is the one region whose create_bucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG_SET})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _allow_cloudfront_oac(s3, bucket, dist_arn) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))


def _cf_b64(raw: bytes) -> str:
    """CloudFront's URL-safe base64 variant: '+'->'-', '='->'_', '/'->'~'.

    Not RFC 4648 urlsafe, which CloudFront would reject."""
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


def _cookie_set(resource: str, expires: int, private_key, key_pair_id: str) -> dict[str, str]:
    """The three signed-cookie name/value pairs for a custom policy.

    CloudFront reads the policy from the cookie, so the signature covers the exact bytes sent."""
    policy = (
        '{"Statement":[{"Resource":"' + resource + '",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + '}}}]}'
    ).encode()
    signature = private_key.sign(policy, padding.PKCS1v15(), hashes.SHA1())
    return {
        "CloudFront-Policy": _cf_b64(policy),
        "CloudFront-Signature": _cf_b64(signature),
        "CloudFront-Key-Pair-Id": key_pair_id,
    }


def _xml_code(text: str) -> str:
    """The CloudFront error document's Code element, or '' when the body is not that document."""
    try:
        return ET.fromstring(text).findtext("Code") or ""
    except ET.ParseError:
        return ""


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Signed cookies with a wildcard custom policy admit every object under the prefix.

    No cookies are refused with MissingKey, an expired policy with a different code, and neither
    refusal leaks protected bytes; the valid cookie set is admitted again afterwards.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-custom-policy.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfcookie-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    key_a = "private/a.txt"
    key_b = "private/b.txt"
    body_a = b"sim2real-cookie-protected-object-a"
    body_b = b"sim2real-cookie-protected-object-b"
    s3.put_object(Bucket=bucket, Key=key_a, Body=body_a, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=key_b, Body=body_b, ContentType="text/plain")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    public_key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfcookie-pk-"),
        "Name": ctx.unique_name("sim2real-behav-cfcookie-pk-"),
        "EncodedKey": pem,
        "Comment": "sim2real signed cookies",
    })["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_public_key, cf.delete_public_key,
                                             public_key_id))

    key_group_id = cf.create_key_group(KeyGroupConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcookie-kg-"),
        "Items": [public_key_id],
        "Comment": "sim2real signed cookies",
    })["KeyGroup"]["Id"]
    # Registered AFTER the public key's cleanup so LIFO deletes the group first: a public key that
    # is still a member of a key group cannot be deleted.
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_key_group, cf.delete_key_group, key_group_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcookie-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfcookie-cr-"),
        "Comment": "sim2real signed cookies with a custom policy",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            # https-only: a signed cookie must never be sent over cleartext, and CloudFront's own
            # guidance marks these cookies Secure.
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])
    _wait_distribution_deployed(cf, dist_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url_a = f"{edge}/{key_a}"
    url_b = f"{edge}/{key_b}"
    # One wildcard resource for the whole prefix: the custom policy's defining capability.
    wildcard = f"{urllib.parse.urlsplit(edge).scheme}://{domain}/private/*"
    valid = _cookie_set(wildcard, int(time.time()) + 900, private_key, public_key_id)
    expired = _cookie_set(wildcard, int(time.time()) - 600, private_key, public_key_id)

    # BEAT 1 — positive control, polled because the distribution has only just deployed.
    def signed_probe():
        try:
            return session.get(url_a, cookies=valid, timeout=15)
        except requests.RequestException as exc:  # transport only
            return exc

    try:
        admitted = _poll_until(
            signed_probe,
            lambda r: isinstance(r, requests.Response) and r.status_code == 200,
            timeout_s=180.0, interval_s=5.0,
            description="200 for the correctly signed cookie set",
        )
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    assert admitted.content == body_a, (
        f"the admitted request served the wrong bytes: expected {body_a!r}, got "
        f"{admitted.content[:120]!r}"
    )

    # BEAT 2 — the wildcard leg: the SAME credential, a DIFFERENT object under the prefix.
    second = session.get(url_b, cookies=valid, timeout=15)
    assert second.status_code == 200, (
        f"a custom policy with Resource={wildcard!r} must admit every object under the prefix: "
        f"expected 200 for /{key_b}, got {second.status_code} / {second.text[:200]!r} — a target "
        f"that only compares Resource to the exact URL (a canned policy) fails here"
    )
    assert second.content == body_b, (
        f"expected {body_b!r} for the second object, got {second.content[:120]!r}"
    )

    # BEAT 3 — break exactly one thing: no credential at all.
    missing = session.get(url_a, timeout=15)
    assert missing.status_code == 403, (
        f"a request with no signed cookies must be refused: expected 403, got "
        f"{missing.status_code} / {missing.text[:200]!r}"
    )
    missing_code = _xml_code(missing.text)
    assert missing_code == "MissingKey", (
        f"expected the CloudFront error document to name MissingKey for a request carrying no "
        f"credential, got {missing_code!r} / {missing.text[:200]!r}"
    )

    # BEAT 4 — break exactly one OTHER thing: a valid signature over an EXPIRED policy.
    stale = session.get(url_a, cookies=expired, timeout=15)
    assert stale.status_code == 403, (
        f"a correctly signed but expired custom policy must be refused: expected 403, got "
        f"{stale.status_code} / {stale.text[:200]!r}"
    )
    stale_code = _xml_code(stale.text)
    # The docs give only "403 Access Denied"; the contract is a code other than MissingKey.
    assert stale_code != "", (
        f"expected a CloudFront error document naming the reason for the expired policy, got "
        f"{stale.text[:200]!r}"
    )
    assert stale_code != missing_code, (
        f"an expired policy and an absent credential are different refusals and CloudFront names "
        f"them differently: both came back as {stale_code!r}, so the target is not evaluating the "
        f"policy's DateLessThan at all"
    )

    # BEAT 5 — effect absent: neither refusal leaked the protected bytes.
    for label, resp in (("no-cookie", missing), ("expired-policy", stale)):
        assert body_a not in resp.content and body_b not in resp.content, (
            f"the {label} refusal body contains protected bytes: {resp.content[:200]!r}"
        )

    # BEAT 6 — restore: the identical admitted call still works.
    restored = session.get(url_a, cookies=valid, timeout=15)
    assert restored.status_code == 200, (
        f"after the two refusals the original cookie set must still be admitted: expected 200, got "
        f"{restored.status_code} / {restored.text[:200]!r}"
    )
    assert restored.content == body_a, (
        f"expected {body_a!r} on the restore leg, got {restored.content[:120]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
