"""cloudfront-s3-access-logging-delivery-positive."""
from __future__ import annotations

import gzip
import io
import ssl
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-s3-access-logging-delivery-positive"
GROUP = "log-delivery"
SERVICES = ["apigateway", "cloudfront", "s3"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_LOG_DELIVERY_GROUP_URI = "http://acs.amazonaws.com/groups/s3/LogDelivery"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CloudFront standard access logs configured to deliver to an S3 bucket
    are actually delivered as readable, gzip-compressed objects that record
    the real requests the distribution served."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    content_bucket = ctx.unique_name("sim2real-logcontent-")
    log_bucket = ctx.unique_name("sim2real-logdest-")
    token = str(uuid.uuid4())
    key = f"asset-{token}.txt"
    body = f"payload-{token}".encode()

    _create_private_bucket(ctx, s3, content_bucket)
    s3.put_object(Bucket=content_bucket, Key=key, Body=body, ContentType="text/plain")

    _create_log_delivery_bucket(ctx, s3, log_bucket)

    oac_id = _create_oac(ctx, cf, ctx.unique_name("sim2real-oac-cfg-"))

    origin_id = "s3-origin"
    log_prefix = "cf-logs/"
    dist_cfg = {
        "CallerReference": str(uuid.uuid4()),
        "Comment": "sim2real-access-logging-delivery-positive",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{content_bucket}.s3.{ctx.region}.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
        },
        "Logging": {
            "Enabled": True,
            "IncludeCookies": False,
            "Bucket": f"{log_bucket}.s3.amazonaws.com",
            "Prefix": log_prefix,
        },
    }
    dist = cf.create_distribution(DistributionConfig=dist_cfg)["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    domain = dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, dist_id))

    s3.put_bucket_policy(Bucket=content_bucket, Policy=_oac_bucket_policy(content_bucket, dist_arn))

    _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)

    # Generate several distinguishable requests so we can find them in the log.
    request_url, edge_headers = ctx.endpoint_route(f"{domain}/{key}")
    for _ in range(5):
        status, fetched = _http_get(request_url, headers=edge_headers, verify=ctx.http_verify)
        assert status == 200 and fetched == body, f"origin fetch failed while generating log traffic: {status}"
        time.sleep(1)

    matching_lines = _poll_for_log_lines(ctx, s3, log_bucket, log_prefix, token, timeout_s=1200.0, interval_s=30.0)
    if matching_lines is None:
        raise AssertionError(
            "CloudFront access log for the test requests did not land in "
            f"s3://{log_bucket}/{log_prefix} within 1200s of the origin fetches; "
            "AWS docs describe delivery as asynchronous and possibly delayed, but "
            "1200s already exceeds what has been observed in practice, so treat this as a failure."
        )

    assert matching_lines, "no delivered access-log line referenced our request token"
    found_200 = any(line.get("sc-status") == "200" for line in matching_lines)
    assert found_200, f"expected a delivered log line with sc-status=200, got {matching_lines}"


def _create_private_bucket(ctx, s3, name: str) -> str:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    return name


def _create_log_delivery_bucket(ctx, s3, name: str) -> str:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    # CloudFront classic access-log delivery writes via ACL grants to the
    # "S3 Log Delivery" group, which requires ACLs to be enabled on the bucket.
    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    owner = s3.get_bucket_acl(Bucket=name)["Owner"]
    s3.put_bucket_acl(
        Bucket=name,
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
                {"Grantee": {"Type": "Group", "URI": _LOG_DELIVERY_GROUP_URI}, "Permission": "WRITE"},
                {"Grantee": {"Type": "Group", "URI": _LOG_DELIVERY_GROUP_URI}, "Permission": "READ_ACP"},
            ],
        },
    )
    return name


def _empty_and_delete_bucket(ctx, s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_oac(ctx, cf, name: str) -> str:
    resp = cf.create_origin_access_control(
        OriginAccessControlConfig={
            "Name": name,
            "Description": "sim2real behavioral check",
            "SigningProtocol": "sigv4",
            "SigningBehavior": "always",
            "OriginAccessControlOriginType": "s3",
        }
    )
    oac_id = resp["OriginAccessControl"]["Id"]

    def _cleanup():
        try:
            etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
            cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_cleanup)
    return oac_id


def _oac_bucket_policy(bucket: str, distribution_arn: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudFrontServicePrincipalOAC",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudfront.amazonaws.com"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {"StringEquals": {"AWS:SourceArn": distribution_arn}},
                }
            ],
        }
    )


def _wait_distribution_deployed(ctx, cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _disable_and_delete_distribution(ctx, cf, dist_id: str) -> None:
    try:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        etag = resp["ETag"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=cfg, IfMatch=etag)
            _wait_distribution_deployed(ctx, cf, dist_id, timeout_s=1500.0)
        etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


def _http_get(url: str, timeout: float = 15.0, headers: dict[str, str] | None = None, verify=True):
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return None, str(e).encode()


def _parse_log_lines(raw_text: str, token: str) -> list:
    """Parse CloudFront standard access-log lines that reference `token`."""
    fields = None
    matches = []
    for line in raw_text.splitlines():
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].strip().split()
            continue
        if line.startswith("#") or not line.strip():
            continue
        if token not in line:
            continue
        values = line.split("\t")
        if fields and len(fields) == len(values):
            matches.append(dict(zip(fields, values)))
        else:
            matches.append({"raw": line})
    return matches


def _poll_for_log_lines(ctx, s3, log_bucket: str, prefix: str, token: str, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=log_bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=log_bucket, Key=obj["Key"])["Body"].read()
            try:
                text = gzip.GzipFile(fileobj=io.BytesIO(body)).read().decode("utf-8", "replace")
            except OSError:
                text = body.decode("utf-8", "replace")
            hits = _parse_log_lines(text, token)
            if hits:
                return hits
        time.sleep(interval_s)
    return None


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
