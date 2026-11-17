"""tenant-only-distribution-routing-endpoint-rejects-direct-viewer-request."""
from __future__ import annotations

import json
import ssl
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-only-distribution-routing-endpoint-rejects-direct-viewer-request"
GROUP = "multi-tenant-distribution"
SERVICES = ["acm", "cloudfront", "s3"]

#: CloudFront's control plane is global and answers only in us-east-1.
CLOUDFRONT_REGION = "us-east-1"
#: The managed CachingOptimized cache policy.
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
#: CloudFront's tenant-parameter syntax: each tenant's TenantPath value is substituted at the edge.
TENANT_ORIGIN_PATH = "/{{TenantPath}}"
#: Deploying a tenant-only distribution, and disabling it before delete, each take 150-300s;
#: the deadline is roughly 3x that.
_DEPLOYED_DEADLINE_S = 900


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A tenant-only distribution reports DomainName '-', and a viewer request addressed to its
    default connection group's own routing endpoint fails the TLS handshake before any request
    reaches the origin, even though the connection group and its tenant are both Deployed.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")
    tok = ctx.unique_name("sim2real-cfrej-").lower()

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": tok,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    bucket = tok
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })

    dist = cf.create_distribution(DistributionConfig=_tenant_only_config(
        tok, f"{bucket}.s3.{ctx.region}.amazonaws.com", oac_id,
    ))["Distribution"]
    dist_id, dist_arn = dist["Id"], dist["ARN"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist_id))
    # Registered after the distribution so it runs FIRST under LIFO: emptying and deleting the
    # bucket is fast, while the distribution's disable-wait-delete is not, and the two must not
    # share a budget that starves the fast one.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))
    # A canary at the literal, unsubstituted path: if a viewer request ever reached the origin
    # without TenantPath resolved, this is the object it would retrieve.
    s3.put_object(Bucket=bucket, Key="{{TenantPath}}/index.html", Body=b"unsubstituted-placeholder",
                  ContentType="text/plain")

    tenant_name = f"{tok}-t"[:64]
    tenant_domain = f"{tok}.test"
    tenant = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": tenant_domain}],
        Enabled=True,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )["DistributionTenant"]
    tenant_id, connection_group_id = tenant["Id"], tenant["ConnectionGroupId"]
    cert_arn = cf.get_managed_certificate_details(Identifier=tenant_id)[
        "ManagedCertificateDetails"]["CertificateArn"]
    # Registered before the tenant so it runs AFTER the tenant's delete under LIFO: the tenant's
    # managed certificate stays in use until the tenant referencing it is gone.
    ctx.on_cleanup(lambda: _delete_certificate(ctx.client("acm", region=CLOUDFRONT_REGION), cert_arn))
    ctx.on_cleanup(lambda: _delete_tenant(cf, tenant_id))

    got = cf.get_distribution(Id=dist_id)["Distribution"]
    assert got.get("DomainName") == "-", (
        f"a tenant-only distribution is reached only through its tenants' domains and reports "
        f"DomainName '-'; got {got.get('DomainName')!r}"
    )

    _wait_distribution_deployed(cf, dist_id)
    connection_group = _wait_connection_group_deployed(cf, connection_group_id)
    assert connection_group["IsDefault"] is True, (
        f"the first tenant on a distribution with no connection group of its own is assigned the "
        f"default one; IsDefault reads {connection_group['IsDefault']!r}"
    )
    routing_endpoint = connection_group["RoutingEndpoint"]
    _wait_tenant_deployed(cf, tenant_id)

    reason = _tls_handshake_rejection(ctx, f"{routing_endpoint}/index.html")
    assert reason == "SSLV3_ALERT_HANDSHAKE_FAILURE", (
        f"a viewer request addressed to the connection group's own routing endpoint, rather than "
        f"to a tenant domain CNAMEd to it, was expected to fail the TLS handshake with "
        f"SSLV3_ALERT_HANDSHAKE_FAILURE; got {reason!r}"
    )


def _find_ssl_error(exc: BaseException) -> ssl.SSLError | None:
    """The ``ssl.SSLError`` nested anywhere in ``exc``'s cause/context/args/reason chain."""
    seen: set[int] = set()
    frontier = [exc]
    while frontier:
        current = frontier.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return current
        for candidate in (current.__cause__, current.__context__, getattr(current, "reason", None)):
            if isinstance(candidate, BaseException):
                frontier.append(candidate)
        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                frontier.append(arg)
    return None


def _tls_handshake_rejection(ctx, published_host_and_path: str) -> str:
    """The TLS alert reason dialing ``published_host_and_path`` raises; raises itself on success."""
    url, headers = ctx.endpoint_route(published_host_and_path)
    try:
        resp = requests.get(url, headers=headers, timeout=15, verify=ctx.http_verify)
    except requests.exceptions.SSLError as exc:
        found = _find_ssl_error(exc)
        if found is not None and found.reason:
            return found.reason
        raise AssertionError(f"an SSLError with no TLS alert reason was raised: {exc!r}") from exc
    raise AssertionError(
        f"expected the TLS handshake to fail, but the connection succeeded with status "
        f"{resp.status_code} and body {resp.content[:200]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) holds; return it, or fail naming the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id: str) -> None:
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S, interval_s=10.0,
        description=f"distribution {dist_id} reaching Deployed",
    )


def _wait_connection_group_deployed(cf, connection_group_id: str) -> dict:
    return _poll_until(
        lambda: cf.get_connection_group(Identifier=connection_group_id)["ConnectionGroup"],
        lambda cg: cg["Status"] == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S, interval_s=10.0,
        description=f"connection group {connection_group_id} reaching Deployed",
    )


def _wait_tenant_deployed(cf, tenant_id: str) -> None:
    _poll_until(
        lambda: cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]["Status"],
        lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S, interval_s=10.0,
        description=f"distribution tenant {tenant_id} reaching Deployed",
    )


def _delete_oac(cf, oac_id: str) -> None:
    try:
        cf.delete_origin_access_control(Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _delete_tenant(cf, tenant_id: str) -> None:
    try:
        cur = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    dt, etag = cur["DistributionTenant"], cur["ETag"]
    if dt.get("Enabled"):
        etag = cf.update_distribution_tenant(
            Id=tenant_id, IfMatch=etag, Enabled=False,
            Domains=[{"Domain": d["Domain"]} for d in dt["Domains"]],
        )["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _delete_certificate(acm, cert_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Delete the tenant's managed certificate once ACM no longer reports it in use."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _retire_distribution(cf, dist_id: str) -> None:
    """Disable if enabled, wait for Deployed, delete; a failed delete raises."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _tenant_only_config(caller_ref: str, origin_host: str, oac_id: str) -> dict:
    """A multi-tenant distribution config: tenant-only, one S3 origin keyed by {{TenantPath}}."""
    return {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant routing endpoint",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginPath": TENANT_ORIGIN_PATH,
            "OriginAccessControlId": oac_id,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "S3Origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "CachePolicyId": CACHING_OPTIMIZED,
            "Compress": True,
        },
        "HttpVersion": "http2",
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True,
                              "MinimumProtocolVersion": "TLSv1.2_2021"},
        "TenantConfig": {"ParameterDefinitions": [{
            "Name": "TenantPath",
            "Definition": {"StringSchema": {"Comment": "S3 keyspace prefix for this tenant",
                                            "Required": False, "DefaultValue": "root"}},
        }]},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
