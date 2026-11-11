"""invalidation-for-tenant-lifecycle."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS-managed CachePolicy id for "Managed-CachingOptimized".
MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _wait_distribution_status(cf, dist_id, status, *, timeout_s=240, interval_s=5):
    return _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == status,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} reaching status {status}",
    )

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _delete_managed_certificate(ctx, domain, *, timeout_s=120, interval_s=5):
    """Find and delete the ACM certificate ManagedCertificateRequest provisioned for
    domain (CloudFront certs live in us-east-1); GetDistributionTenant does not surface
    its ARN for a self-hosted managed-certificate request, so look it up by domain name.
    The cert stays briefly in use right after the tenant referencing it is deleted, so
    retry past ResourceInUseException instead of leaking it."""
    acm = ctx.client("acm", region="us-east-1")  # CloudFront certificates must live in us-east-1
    # list_certificates only returns RSA_2048 certs unless every key type is asked for.
    key_types = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]
    cert_arn = None
    for page in acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": key_types}):
        for summary in page["CertificateSummaryList"]:
            if summary.get("DomainName") == domain:
                cert_arn = summary["CertificateArn"]
                break
        if cert_arn:
            break
    if cert_arn is None:
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _delete_distribution_tenant(cf, tenant_id):
    cur = cf.get_distribution_tenant(Identifier=tenant_id)
    if cur["DistributionTenant"].get("Enabled"):
        cur = cf.update_distribution_tenant(
            Id=tenant_id,
            IfMatch=cur["ETag"],
            Enabled=False,
            Domains=[{"Domain": d["Domain"]} for d in cur["DistributionTenant"]["Domains"]],
        )
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=cur["ETag"])

def _short_unique_name(max_len=32):
    return ("sim2real-behav-" + uuid.uuid4().hex)[:max_len]

def _minimal_multi_tenant_distribution_config(name):
    origin_domain = f"{name}.s3.amazonaws.com"
    return {
        "CallerReference": name,
        "Comment": name,
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {
            "ParameterDefinitions": [
                {
                    "Name": "tenantName",
                    "Definition": {
                        "StringSchema": {
                            "Comment": "tenant name",
                            "DefaultValue": "root",
                            "Required": False,
                        }
                    },
                }
            ]
        },
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "OriginPath": "/{{tenantName}}",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
        },
    }

def _create_multi_tenant_distribution_and_tenant(cf, ctx, prefix="sim2real-behav-mtd-"):
    """Create a multi-tenant Distribution + one DistributionTenant on it.
    Returns ``(dist_id, tenant_id, tenant_domain)``; both are registered for cleanup."""
    name = ctx.unique_name(prefix)
    create_resp = cf.create_distribution(
        DistributionConfig=_minimal_multi_tenant_distribution_config(name)
    )
    dist_id = create_resp["Distribution"]["Id"]
    dist_arn = create_resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real-check", "Value": "invalidation-for-tenant-lifecycle"}]})
    # A slow multi-tenant distribution deploy raises a clear timeout rather than
    # running past the per-check ceiling and being SIGKILLed with no diagnosis.
    try:
        _wait_distribution_status(cf, dist_id, "Deployed", timeout_s=900, interval_s=10)
    except AssertionError as exc:
        raise AssertionError(
            f"multi-tenant distribution did not reach Deployed within the "
            f"per-check budget: {exc}",
        ) from exc

    tenant_name = _short_unique_name(28)
    domain = f"{tenant_name}.sim2real.test"
    dt_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        Tags={"Items": [{"Key": "sim2real-check", "Value": "invalidation-for-tenant-lifecycle"}]},
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
    )
    tenant_id = dt_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_managed_certificate(ctx, domain))
    ctx.on_cleanup(lambda: _delete_distribution_tenant(cf, tenant_id))
    return dist_id, tenant_id, domain

CHECK = "invalidation-for-tenant-lifecycle"
GROUP = 'distribution-tenant'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Distribution-tenant-scoped invalidation: create -> InProgress/Completed
    -> Get and List (scoped to the tenant, not the underlying Distribution)
    all agree."""
    cf = ctx.client("cloudfront")
    dist_id, tenant_id, _domain = _create_multi_tenant_distribution_and_tenant(cf, ctx, prefix="sim2real-behav-itlc-")

    caller_ref = ctx.unique_name("sim2real-behav-inval-tenant-")
    paths = ["/tenant/*"]
    create_resp = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_id,
        InvalidationBatch={"Paths": {"Quantity": len(paths), "Items": paths}, "CallerReference": caller_ref},
    )
    inval_id = create_resp["Invalidation"]["Id"]
    assert create_resp["Invalidation"]["Status"] in ("InProgress", "Completed"), (
        f"expected a freshly created invalidation to start InProgress or Completed, got "
        f"{create_resp['Invalidation']['Status']!r}"
    )
    assert create_resp["Invalidation"]["InvalidationBatch"]["CallerReference"] == caller_ref, (
        f"expected CreateInvalidationForDistributionTenant to echo CallerReference "
        f"{caller_ref!r}, got {create_resp['Invalidation']['InvalidationBatch']['CallerReference']!r}"
    )

    listed = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    ids = [i["Id"] for i in listed["InvalidationList"]["Items"]]
    assert inval_id in ids, f"expected {inval_id} in ListInvalidationsForDistributionTenant, got {ids}"

    # Get (tenant-scoped) agrees on identity and batch regardless of completion.
    got = cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=inval_id)
    assert got["Invalidation"]["Id"] == inval_id, (
        f"expected GetInvalidationForDistributionTenant to return id {inval_id!r}, "
        f"got {got['Invalidation']['Id']!r}"
    )
    assert got["Invalidation"]["InvalidationBatch"]["Paths"]["Items"] == paths, (
        f"expected GetInvalidationForDistributionTenant to agree on paths {paths!r}, "
        f"got {got['Invalidation']['InvalidationBatch']['Paths']['Items']!r}"
    )

    # A bogus invalidation Id against the real tenant must fail distinctly.
    code, message = _error(
        lambda: cf.get_invalidation_for_distribution_tenant(
            DistributionTenantId=tenant_id, Id="IBOGUSTENANTINVAL123"
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assert message == "The specified invalidation does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )

    # Reaching Completed is a slow propagation tail: bound the wait and raise a
    # clear timeout rather than running past the per-check ceiling.
    try:
        final = _poll_until(
            lambda: cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=inval_id),
            lambda r: r["Invalidation"]["Status"] == "Completed",
            timeout_s=180,
            interval_s=3,
            description=f"tenant invalidation {inval_id} reaching Completed",
        )
    except AssertionError as exc:
        raise AssertionError(
            f"tenant invalidation did not reach Completed within the per-check budget: {exc}",
        ) from exc
    assert final["Invalidation"]["Status"] == "Completed", (
        f"expected tenant invalidation {inval_id} to settle on Completed, "
        f"got {final['Invalidation']['Status']!r}"
    )

    # dist_id is unused directly beyond setup — the tenant scoping is the point.
    del dist_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
