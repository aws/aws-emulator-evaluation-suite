"""xsvc-cloudfront-2-oac-kms-key-policy-without-cloudfront-principal-denied."""
from __future__ import annotations

import json
import time
import xml.etree.ElementTree as ET

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-2-oac-kms-key-policy-without-cloudfront-principal-denied"
GROUP = "origin-access-control"
SERVICES = ["cloudfront", "kms", "s3"]

#: CloudFront's control plane is global and signed in us-east-1; the bucket and key use ctx.region.
CLOUDFRONT_REGION = "us-east-1"

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: every edge request reaches S3, so a key-policy change is observable on
#: the very next request instead of being answered out of the edge cache.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_TAGS = [{"Key": "sim2real", "Value": "xsvc-cloudfront-2"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> None:
    _poll_until(lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
                lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distribution(cf, dist_id, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete -- called from the check body on the success path,
    since disable -> Deployed takes minutes."""
    resp = cf.get_distribution_config(Id=dist_id)
    cfg = resp["DistributionConfig"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    _wait_distribution_deployed(cf, dist_id, timeout_s=timeout_s)
    cf.delete_distribution(Id=dist_id, IfMatch=cf.get_distribution(Id=dist_id)["ETag"])


def _retry_in_use(fn, timeout_s=120.0) -> None:
    """A dependent of a just-deleted distribution can briefly still read as *InUse."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if not _code(exc).endswith("InUse") or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _disable_distribution(cf, dist_id) -> None:
    """Failure-path net: disable the distribution without waiting for the change to deploy.

    Disable, deploy and delete takes minutes, longer than the cleanup chain's time bound; the
    success path deletes it in the body (_teardown_distribution), so here it is normally gone.
    """
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        cfg = cfg_resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        raise RuntimeError(f"cloudfront distribution {dist_id} disabled, not deleted (deploy wait exceeds "
                           f"the cleanup bound); its sim2real comment makes it reap_leftovers.py's to delete")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _delete_oac(cf, oac_id) -> None:
    """Failure-path net: delete the OAC (the success path deletes it in the body); CloudFront
    refuses while an undeleted distribution still references it, and that is reported rather
    than retried."""
    try:
        cf.delete_origin_access_control(Id=oac_id,
                                        IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchOriginAccessControl",):
            raise RuntimeError(
                f"origin access control {oac_id}: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _key_policy(account: str, cloudfront_source_arn: str | None) -> str:
    statements = [{
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if cloudfront_source_arn is not None:
        statements.append({
            "Sid": "AllowCloudFrontServicePrincipalSSE-KMS",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceArn": cloudfront_source_arn}},
        })
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _s3_error_code(resp) -> str | None:
    try:
        return ET.fromstring(resp.text).findtext("Code")
    except ET.ParseError:
        return None


def _s3_error_message(resp) -> str | None:
    try:
        return ET.fromstring(resp.text).findtext("Message")
    except ET.ParseError:
        return None


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
    """An OAC-fronted SSE-KMS object is refused at the edge (403) until the key policy admits
    CloudFront scoped by aws:SourceArn to this distribution, while an SSE-S3 object is served.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    key_arn = kms.create_key(
        Description="sim2real xsvc-cloudfront-2 OAC SSE-KMS key",
        Policy=_key_policy(account, None),
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _TAGS],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("kms").schedule_key_deletion(KeyId=key_arn,
                                                                   PendingWindowInDays=7))

    bucket = ctx.unique_name("sim2real-xsvc-cfkms-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    # Bucket Keys OFF: every GetObject then calls KMS Decrypt as the requester, so a key-policy
    # change governs the very next edge request rather than a cached bucket-level data key.
    s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={"Rules": [{
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms",
                                               "KMSMasterKeyID": key_arn},
        "BucketKeyEnabled": False,
    }]})

    kms_key_name, kms_body = "kms/asset.txt", ctx.unique_name("sim2real-kms-bytes-").encode()
    s3_key_name, s3_body = "sse-s3/asset.txt", ctx.unique_name("sim2real-sse-s3-bytes-").encode()
    put_kms = s3.put_object(Bucket=bucket, Key=kms_key_name, Body=kms_body, ContentType="text/plain")
    assert (put_kms.get("ServerSideEncryption"), put_kms.get("SSEKMSKeyId")) == ("aws:kms", key_arn), (
        f"the bucket default must encrypt with the CMK, got "
        f"{(put_kms.get('ServerSideEncryption'), put_kms.get('SSEKMSKeyId'))!r}"
    )
    put_s3 = s3.put_object(Bucket=bucket, Key=s3_key_name, Body=s3_body, ContentType="text/plain",
                           ServerSideEncryption="AES256")
    assert put_s3.get("ServerSideEncryption") == "AES256", (
        f"the barrier object must be SSE-S3, got {put_s3.get('ServerSideEncryption')!r}"
    )

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cfkms-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    # The bucket's regional domain, the form CloudFront takes as an S3 origin.
    bucket_host = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-cfkms-cr-"),
        "Comment": "sim2real xsvc-cloudfront-2 OAC over SSE-KMS",
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
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
        # A 403 from the origin is otherwise cached for 10 s, which would let beat 4's poll read a
        # stale refusal. Zero makes every edge answer the origin's current answer.
        "CustomErrorResponses": {"Quantity": 1, "Items": [
            {"ErrorCode": 403, "ErrorCachingMinTTL": 0},
        ]},
    })["Distribution"]
    dist_id, dist_arn, domain = dist["Id"], dist["ARN"], dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_distribution(cf, dist_id))

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalReadOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))

    _wait_distribution_deployed(cf, dist_id)
    session = requests.Session()
    session.verify = ctx.http_verify
    base, route_headers = ctx.endpoint_route(domain)
    session.headers.update(route_headers)
    kms_url, s3_url = f"{base}/{kms_key_name}", f"{base}/{s3_key_name}"

    def edge(url):
        def probe():
            try:
                return session.get(url, timeout=20)
            except requests.RequestException as exc:  # transport only, during edge propagation
                return exc
        return probe

    # BEAT 1 — barrier: OAC + bucket policy are live.
    try:
        barrier = _poll_until(edge(s3_url),
                              lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                              timeout_s=240.0, interval_s=5.0,
                              description=f"the SSE-S3 object to be served at {s3_url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    assert barrier.content == s3_body, f"the edge served the wrong SSE-S3 bytes: {barrier.content!r}"

    # BEAT 2 — the key policy has no cloudfront principal: S3 cannot decrypt on CloudFront's behalf.
    denied = session.get(kms_url, timeout=20)
    assert denied.status_code == 403, (
        f"the SSE-KMS object must be refused at the edge while the key policy omits "
        f"cloudfront.amazonaws.com: got {denied.status_code!r} / {denied.text[:300]!r}"
    )
    assert _s3_error_code(denied) == "AccessDenied", (
        f"expected S3's AccessDenied passed through the edge, got {_s3_error_code(denied)!r} / "
        f"{denied.text[:300]!r}"
    )
    expected_message = "Access Denied"
    assert _s3_error_message(denied) == expected_message, (
        f"expected S3's refusal message {expected_message!r} passed through the edge, got "
        f"{_s3_error_message(denied)!r}"
    )
    assert kms_body not in denied.content, f"the 403 leaked the object bytes: {denied.content[:200]!r}"
    still = session.get(s3_url, timeout=20)
    assert (still.status_code, still.content) == (200, s3_body), (
        f"in the same instant the SSE-S3 object must still be served, got "
        f"{(still.status_code, still.content[:200])!r}"
    )

    # BEAT 3 — positive control: the object and the key are fine for a KMS-authorized caller.
    direct = s3.get_object(Bucket=bucket, Key=kms_key_name)
    assert (direct["Body"].read(), direct.get("SSEKMSKeyId")) == (kms_body, key_arn), (
        "a direct GetObject with KMS-authorized credentials must return the SSE-KMS object"
    )

    # BEAT 4 — repair exactly one thing: the key policy now admits CloudFront for THIS distribution.
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=_key_policy(account, dist_arn))
    served = _poll_until(edge(kms_url),
                         lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                         timeout_s=180.0, interval_s=5.0,
                         description="the SSE-KMS object to be served once the key policy admits "
                                     "cloudfront.amazonaws.com")
    assert served.content == kms_body, f"the edge served the wrong SSE-KMS bytes: {served.content!r}"

    # BEAT 5 — the aws:SourceArn scope is enforced: a grant for another distribution admits nothing.
    other_arn = f"arn:aws:cloudfront::{account}:distribution/E{ctx.unique_name('').upper()[:13]}"
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=_key_policy(account, other_arn))
    rescoped = _poll_until(edge(kms_url),
                           lambda r: isinstance(r, requests.Response) and r.status_code == 403,
                           timeout_s=180.0, interval_s=5.0,
                           description="the edge to refuse again once the grant names another "
                                       "distribution's ARN")
    assert _s3_error_code(rescoped) == "AccessDenied", (
        f"expected AccessDenied after re-scoping, got {_s3_error_code(rescoped)!r} / "
        f"{rescoped.text[:300]!r}"
    )
    assert kms_body not in rescoped.content, (
        f"the re-scoped 403 leaked the object bytes: {rescoped.content[:200]!r}"
    )

    # --- teardown of the slow chain, in the body (see _teardown_distribution) ------------------
    _teardown_distribution(cf, dist_id)
    _retry_in_use(lambda: cf.delete_origin_access_control(
        Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"]))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
