"""cf-unsigned-request-to-trusted-key-group-distribution-rejected."""
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

CHECK = "cf-unsigned-request-to-trusted-key-group-distribution-rejected"
GROUP = 'security'
SERVICES = ['cloudfront']

#: Marks an edge that never serves the deployed distribution as a data-plane failure of the target.
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

    Create -> Deployed and disable -> Deployed each take a few minutes; 900 s leaves wide margin.
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


def _cf_b64(raw: bytes) -> str:
    """CloudFront's URL-safe base64 variant: '+'->'-', '='->'_', '/'->'~'.

    Its own alphabet, not RFC 4648 urlsafe (which maps '/'->'_' and leaves '=' as padding), so
    base64.urlsafe_b64encode would produce a signature CloudFront rejects.
    """
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


def _signed_url(url: str, expires: int, private_key, key_pair_id: str) -> str:
    """A canned-policy CloudFront signed URL.

    The signature is RSA-SHA1 over the exact canned policy document, with no whitespace: CloudFront
    reconstructs the same string from Resource + Expires and compares, so any reformatting of the
    JSON invalidates it. That is why the policy is a literal f-string rather than json.dumps output.
    """
    policy = (
        '{"Statement":[{"Resource":"' + url + '",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + '}}}]}'
    )
    signature = private_key.sign(policy.encode(), padding.PKCS1v15(), hashes.SHA1())
    return (f"{url}?Expires={expires}&Signature={_cf_b64(signature)}"
            f"&Key-Pair-Id={key_pair_id}")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An unsigned request to a trusted-key-group behavior is refused at the edge with MissingKey,
    while the same URL signed with the trusted key returns the object's exact bytes.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfsig-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    key = "private.txt"
    body = b"sim2real-signed-url-protected-object"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    public_key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfsig-pk-"),
        "Name": ctx.unique_name("sim2real-behav-cfsig-pk-"),
        "EncodedKey": pem,
        "Comment": "sim2real trusted key group",
    })["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_public_key, cf.delete_public_key,
                                             public_key_id))

    key_group_id = cf.create_key_group(KeyGroupConfig={
        "Name": ctx.unique_name("sim2real-behav-cfsig-kg-"),
        "Items": [public_key_id],
        "Comment": "sim2real trusted key group",
    })["KeyGroup"]["Id"]
    # Registered AFTER the public key's cleanup so LIFO deletes the group first: a public key that
    # is still a member of a key group cannot be deleted.
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_key_group, cf.delete_key_group, key_group_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfsig-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfsig-cr-"),
        "Comment": "sim2real trusted key group enforcement",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # managed CachingDisabled
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
        },
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]

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
    url = f"{edge}/{key}"
    published_url = f"{urllib.parse.urlsplit(edge).scheme}://{domain}/{key}"
    expires = int(time.time()) + 900

    # POSITIVE CONTROL FIRST, and it doubles as the proof that the edge, the OAC and the bucket
    # policy are all working: only then is a 403 on the unsigned request attributable to the
    # signature and nothing else.
    def signed_probe():
        try:
            signed_url, _ = ctx.endpoint_route(_signed_url(published_url, expires, private_key, public_key_id))
            return session.get(signed_url, timeout=15)
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            return exc

    try:
        signed = _poll_until(
            signed_probe,
            lambda r: isinstance(r, requests.Response) and r.status_code == 200,
            timeout_s=180, interval_s=5,
            description="200 for the correctly signed URL",
        )
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc

    assert signed.status_code == 200, (
        f"the correctly signed URL was refused: {signed.status_code!r} / {signed.text[:200]!r}"
    )
    assert signed.content == body, (
        f"the signed request served the wrong bytes: {signed.content!r}"
    )

    unsigned = session.get(url, timeout=15)
    assert unsigned.status_code == 403, (
        f"an unsigned request to a trusted-key-group behavior was served: "
        f"{unsigned.status_code!r} / {unsigned.text[:200]!r}"
    )
    xml_code = ET.fromstring(unsigned.text).findtext("Code")
    assert xml_code == "MissingKey", (
        f"expected the CloudFront error body to name MissingKey, got {xml_code!r} / "
        f"{unsigned.text[:200]!r}"
    )
    # Effect absent: the refusal must not have leaked any of the object's bytes.
    assert body not in unsigned.content, (
        f"the 403 body contains the protected object's bytes: {unsigned.content[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
