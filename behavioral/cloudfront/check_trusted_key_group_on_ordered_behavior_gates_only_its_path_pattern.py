"""trusted-key-group-on-ordered-behavior-gates-only-its-path-pattern."""
from __future__ import annotations

import base64
import json
import time
import xml.etree.ElementTree as ET

import requests
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "trusted-key-group-on-ordered-behavior-gates-only-its-path-pattern"
GROUP = "security"
SERVICES = ["cloudfront"]

_NO_CACHE_POLICY = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed CachingDisabled
_GATED_PATTERN = "/members/*"
_GATED_KEY = "members/ledger.txt"
_OPEN_KEY = "open/notice.txt"
_GATED_BYTES = b"members-only ledger served through the gated behavior"
_OPEN_BYTES = b"public notice served through the ungated default behavior"
_REFUSED_CODE = "MissingKey"
_REFUSED_MESSAGE = "Missing Key-Pair-Id query parameter or cookie value"


def _undo(call, *gone: str):
    """A cleanup that runs ``call()`` and raises unless the resource is already ``gone``."""

    def apply() -> None:
        try:
            call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise

    return apply


def _settle(read, accept, *, limit_s: float, step_s: float, what: str):
    """Re-``read()`` until ``accept()`` holds; raise naming ``what`` when the budget runs out."""
    give_up = time.monotonic() + limit_s
    seen = None
    while True:
        seen = read()
        if accept(seen):
            return seen
        if time.monotonic() >= give_up:
            raise AssertionError(f"{what} never held within {limit_s}s; last answer was {seen!r}")
        time.sleep(step_s)


def _deployed_etag(cf, dist_id: str) -> str:
    """Wait for the distribution to reach Deployed and return the ETag of that read."""
    latest = {"etag": ""}

    def read() -> str:
        answer = cf.get_distribution(Id=dist_id)
        latest["etag"] = answer["ETag"]
        return answer["Distribution"]["Status"]

    _settle(read, lambda state: state == "Deployed", limit_s=600.0, step_s=10.0,
            what=f"distribution {dist_id} reaching Deployed")
    return latest["etag"]


def _retire(cf, dist_id: str) -> None:
    """Switch the distribution off, let that land, then delete it."""
    try:
        held = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    config = held["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=held["ETag"], DistributionConfig=config)
    cf.delete_distribution(Id=dist_id, IfMatch=_deployed_etag(cf, dist_id))


def _drain(s3, bucket: str) -> None:
    """Remove every object the check put in ``bucket``, then the bucket."""
    try:
        pages = list(s3.get_paginator("list_objects_v2").paginate(Bucket=bucket))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for page in pages:
        doomed = [{"Key": entry["Key"]} for entry in page.get("Contents", [])]
        if doomed:
            left = s3.delete_objects(Bucket=bucket, Delete={"Objects": doomed}).get("Errors")
            if left:
                raise RuntimeError(f"DeleteObjects could not remove {len(left)} object(s): {left[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _spki(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _cloudfront_alphabet(raw: bytes) -> str:
    """CloudFront's own base64 alphabet for signature and policy query values."""
    return base64.b64encode(raw).decode().translate(str.maketrans("+=/", "-_~"))


def _canned_url(url: str, deadline: int, private_key, key_id: str) -> str:
    """``url`` plus a canned-policy signature; the signed bytes must be CloudFront's exact form."""
    statement = (
        '{"Statement":[{"Resource":"' + url + '",'
        '"Condition":{"DateLessThan":{"AWS:EpochTime":' + str(deadline) + '}}}]}'
    )
    signed = private_key.sign(statement.encode(), padding.PKCS1v15(), hashes.SHA1())
    return (f"{url}?Expires={deadline}&Signature={_cloudfront_alphabet(signed)}"
            f"&Key-Pair-Id={key_id}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A trusted key group on one ordered cache behavior gates only that path pattern: the
    default behavior still serves unsigned viewers while the gated path refuses them and
    admits the same request once it carries a signature from the group's key.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    origin_bucket = ctx.unique_name("sim2real-behav-cfgate-").lower()
    # us-east-1 is the one region S3 refuses a LocationConstraint for, so it is named here.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=origin_bucket)
    else:
        s3.create_bucket(Bucket=origin_bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _drain(ctx.client("s3"), origin_bucket))
    s3.put_object(Bucket=origin_bucket, Key=_OPEN_KEY, Body=_OPEN_BYTES, ContentType="text/plain")
    s3.put_object(Bucket=origin_bucket, Key=_GATED_KEY, Body=_GATED_BYTES, ContentType="text/plain")

    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_name = ctx.unique_name("sim2real-behav-cfgate-pk-")
    signer_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": signer_name,
        "Name": signer_name,
        "EncodedKey": _spki(signer),
        "Comment": "path-scoped signing probe",
    })["PublicKey"]["Id"]
    ctx.on_cleanup(_undo(
        lambda: cf.delete_public_key(Id=signer_id,
                                     IfMatch=cf.get_public_key(Id=signer_id)["ETag"]),
        "NoSuchPublicKey"))

    group_name = ctx.unique_name("sim2real-behav-cfgate-kg-")
    group_id = cf.create_key_group(KeyGroupConfig={
        "Name": group_name, "Items": [signer_id], "Comment": "path-scoped signing probe",
    })["KeyGroup"]["Id"]
    # Registered after the key, so LIFO drops the group before the key it holds.
    ctx.on_cleanup(_undo(
        lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"]),
        "NoSuchResource"))

    access_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfgate-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(_undo(
        lambda: cf.delete_origin_access_control(
            Id=access_id, IfMatch=cf.get_origin_access_control(Id=access_id)["ETag"]),
        "NoSuchOriginAccessControl"))

    ungated = {
        "TargetOriginId": "ledger-origin",
        "ViewerProtocolPolicy": "https-only",
        "CachePolicyId": _NO_CACHE_POLICY,
    }
    distribution = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfgate-ref-"),
        "Comment": "sim2real path-scoped signing probe",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "ledger-origin",
            "DomainName": f"{origin_bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": access_id,
        }]},
        "DefaultCacheBehavior": dict(ungated),
        "CacheBehaviors": {"Quantity": 1, "Items": [dict(
            ungated,
            PathPattern=_GATED_PATTERN,
            TrustedKeyGroups={"Enabled": True, "Quantity": 1, "Items": [group_id]},
        )]},
    })["Distribution"]
    gateway_id = distribution["Id"]
    # Registered last, so LIFO retires the distribution before the resources it references.
    ctx.on_cleanup(lambda: _retire(cf, gateway_id))
    edge_host = distribution["DomainName"]

    s3.put_bucket_policy(Bucket=origin_bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{origin_bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": distribution["ARN"]}},
        }],
    }))

    _deployed_etag(cf, gateway_id)

    stored = cf.get_distribution_config(Id=gateway_id)["DistributionConfig"]
    assert stored["DefaultCacheBehavior"].get("TrustedKeyGroups", {}).get("Enabled") is False, (
        "the default behavior must stay ungated, but its stored TrustedKeyGroups read "
        f"{stored['DefaultCacheBehavior'].get('TrustedKeyGroups')!r}"
    )
    ordered = stored["CacheBehaviors"]["Items"][0]
    assert ordered["PathPattern"] == _GATED_PATTERN, (
        f"the ordered behavior's stored PathPattern is {ordered['PathPattern']!r}, "
        f"expected {_GATED_PATTERN!r}"
    )
    assert ordered["TrustedKeyGroups"]["Items"] == [group_id], (
        "the ordered behavior must hold exactly the key group the check created, but it holds "
        f"{ordered['TrustedKeyGroups']['Items']!r}"
    )

    viewer = requests.Session()
    base, extra = ctx.endpoint_route(edge_host)
    viewer.headers.update(extra)
    scheme = base.split("://", 1)[0]
    open_url = f"{scheme}://{edge_host}/{_OPEN_KEY}"
    gated_url = f"{scheme}://{edge_host}/{_GATED_KEY}"
    deadline = int(time.time()) + 1800

    def get(target: str):
        dialed, _ = ctx.endpoint_route(target)
        try:
            return viewer.get(dialed, timeout=15, verify=ctx.http_verify)
        except requests.RequestException as exc:  # the edge can refuse a connection while it lands
            return exc

    def answered(code: int):
        return lambda seen: isinstance(seen, requests.Response) and seen.status_code == code

    # The ungated path is the positive control: it proves the origin, the access control and the
    # viewer's own route all work, so a refusal further down can only come from the key group.
    served = _settle(lambda: get(open_url), answered(200), limit_s=240.0, step_s=10.0,
                     what="an unsigned viewer being served the default behavior's path")
    assert served.content == _OPEN_BYTES, (
        f"the ungated path served {served.content!r}, expected {_OPEN_BYTES!r}"
    )

    refused = get(gated_url)
    assert isinstance(refused, requests.Response), (
        f"the unsigned request to the gated path never completed: {refused!r}"
    )
    assert refused.status_code == 403, (
        f"an unsigned request to {_GATED_PATTERN!r} was answered {refused.status_code!r}, "
        f"expected 403: {refused.text[:200]!r}"
    )
    envelope = ET.fromstring(refused.text)
    assert envelope.findtext("Code") == _REFUSED_CODE, (
        f"the refusal named {envelope.findtext('Code')!r}, expected {_REFUSED_CODE!r}"
    )
    assert envelope.findtext("Message") == _REFUSED_MESSAGE, (
        f"the refusal read {envelope.findtext('Message')!r}, expected {_REFUSED_MESSAGE!r}"
    )
    assert _GATED_BYTES not in refused.content, (
        f"the refusal leaked the gated object: {refused.content[:200]!r}"
    )

    admitted = _settle(lambda: get(_canned_url(gated_url, deadline, signer, signer_id)),
                       answered(200), limit_s=240.0, step_s=10.0,
                       what="the group's key admitting the same gated path")
    assert admitted.content == _GATED_BYTES, (
        f"the signed request served {admitted.content!r}, expected {_GATED_BYTES!r}"
    )

    still_open = get(open_url)
    assert isinstance(still_open, requests.Response) and still_open.status_code == 200, (
        f"the ungated path stopped serving unsigned viewers: {still_open!r}"
    )
    assert still_open.content == _OPEN_BYTES, (
        f"the ungated path served {still_open.content!r}, expected {_OPEN_BYTES!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
