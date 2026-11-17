"""signed-url-key-outside-trusted-key-group-rejected."""
from __future__ import annotations

import base64
import json
import time
import urllib.parse
import xml.etree.ElementTree as ET

import requests
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "signed-url-key-outside-trusted-key-group-rejected"
GROUP = "security"
SERVICES = ["cloudfront"]

_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed cache policy
_EDGE_REFUSAL = "InvalidKey"
_EDGE_REFUSAL_MESSAGE = "Unknown Key"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id, *, timeout_s=600.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=10.0,
                description=f"distribution {dist_id} Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for the change to deploy, then delete."""
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = cfg_resp["DistributionConfig"], cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket) -> None:
    try:
        pages = list(s3.get_paginator("list_objects_v2").paginate(Bucket=bucket))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for page in pages:
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _cf_b64(raw: bytes) -> str:
    """CloudFront's URL-safe base64: '+'->'-', '='->'_', '/'->'~'."""
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


def _signed_url(url: str, expires: int, private_key, key_pair_id: str) -> str:
    """A canned-policy signed URL; the policy string must match CloudFront's byte for byte."""
    policy = (
        '{"Statement":[{"Resource":"' + url + '",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(expires) + '}}}]}'
    )
    signature = private_key.sign(policy.encode(), padding.PKCS1v15(), hashes.SHA1())
    return f"{url}?Expires={expires}&Signature={_cf_b64(signature)}&Key-Pair-Id={key_pair_id}"


def _pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A URL signed by a key outside the behavior's trusted key group is refused at the edge,
    and is admitted once UpdateKeyGroup adds that key, while the member key's URL keeps working.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfkr-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    obj_key = "private.txt"
    body = b"sim2real-key-rotation-protected-object"
    s3.put_object(Bucket=bucket, Key=obj_key, Body=body, ContentType="text/plain")

    member_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    outsider_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_ids = {}
    for label, priv in (("member", member_priv), ("outsider", outsider_priv)):
        name = ctx.unique_name(f"sim2real-behav-cfkr-{label}-")
        key_id = cf.create_public_key(PublicKeyConfig={
            "CallerReference": name, "Name": name, "EncodedKey": _pem(priv),
            "Comment": "sim2real key rotation",
        })["PublicKey"]["Id"]
        ctx.on_cleanup(_teardown(
            lambda k=key_id: cf.delete_public_key(Id=k, IfMatch=cf.get_public_key(Id=k)["ETag"]),
            "NoSuchPublicKey"))
        key_ids[label] = key_id

    kg_name = ctx.unique_name("sim2real-behav-cfkr-kg-")
    kg = cf.create_key_group(KeyGroupConfig={"Name": kg_name, "Items": [key_ids["member"]]})
    kg_id = kg["KeyGroup"]["Id"]
    # Registered after the public keys, so LIFO deletes the group before its members.
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_key_group(Id=kg_id, IfMatch=cf.get_key_group(Id=kg_id)["ETag"]),
        "NoSuchResource"))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfkr-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_origin_access_control(
            Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"]),
        "NoSuchOriginAccessControl"))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfkr-cr-"),
        "Comment": "sim2real trusted key group rotation",
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
            "CachePolicyId": _CACHING_DISABLED,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [kg_id]},
        },
    })["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))

    _wait_deployed(cf, dist_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    published_url = f"{urllib.parse.urlsplit(edge).scheme}://{domain}/{obj_key}"
    expires = int(time.time()) + 1800

    def fetch(priv, key_id):
        try:
            url, _ = ctx.endpoint_route(_signed_url(published_url, expires, priv, key_id))
            return session.get(url, timeout=15, verify=ctx.http_verify)
        except requests.RequestException as exc:  # transient while the edge propagates
            return exc

    def is_status(code):
        return lambda r: isinstance(r, requests.Response) and r.status_code == code

    member_ok = _poll_until(lambda: fetch(member_priv, key_ids["member"]), is_status(200),
                            timeout_s=180, description="200 for the member key's signed URL")
    assert member_ok.content == body, f"member-signed URL served wrong bytes: {member_ok.content!r}"

    outsider = fetch(outsider_priv, key_ids["outsider"])
    assert isinstance(outsider, requests.Response), f"outsider request failed: {outsider!r}"
    assert outsider.status_code == 403, (
        f"a URL signed by a key outside the trusted key group was answered "
        f"{outsider.status_code!r}: {outsider.text[:200]!r}"
    )
    doc = ET.fromstring(outsider.text)
    assert doc.findtext("Code") == _EDGE_REFUSAL, (
        f"expected edge error code {_EDGE_REFUSAL!r}, got {outsider.text[:300]!r}"
    )
    assert doc.findtext("Message") == _EDGE_REFUSAL_MESSAGE, (
        f"expected edge error message {_EDGE_REFUSAL_MESSAGE!r}, got {outsider.text[:300]!r}"
    )
    assert body not in outsider.content, f"the 403 leaked the object: {outsider.content[:200]!r}"

    etag = cf.get_key_group(Id=kg_id)["ETag"]
    updated = cf.update_key_group(Id=kg_id, IfMatch=etag, KeyGroupConfig={
        "Name": kg_name, "Items": [key_ids["member"], key_ids["outsider"]]})
    stored = sorted(updated["KeyGroup"]["KeyGroupConfig"]["Items"])
    assert stored == sorted(key_ids.values()), f"key group members after update: {stored!r}"

    admitted = _poll_until(lambda: fetch(outsider_priv, key_ids["outsider"]), is_status(200),
                           timeout_s=420, description="200 for the newly trusted key's URL")
    assert admitted.content == body, f"newly trusted key served wrong bytes: {admitted.content!r}"
    still = fetch(member_priv, key_ids["member"])
    assert isinstance(still, requests.Response) and still.status_code == 200, (
        f"the member key stopped working after the outsider was added: {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
