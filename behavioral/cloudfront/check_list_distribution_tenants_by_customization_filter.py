"""list-distribution-tenants-by-customization-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distribution-tenants-by-customization-filter"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionTenantsByCustomization(WebACLArn=...) returns only the tenant whose
    Customizations reference that WAF web ACL, excluding a sibling tenant on the same
    multi-tenant distribution that has no such customization.
    """
    wafv2 = ctx.client("wafv2")
    acl_name = ctx.unique_name("sim2real-cf-acl-")
    web_acl = wafv2.create_web_acl(
        Name=acl_name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": "sim2realCfAcl",
        },
        Rules=[],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    web_acl_arn = web_acl["ARN"]

    def _cleanup_acl():
        # Retry while the tenant deletions propagate (WAFAssociatedItemException) or a concurrent
        # edit moved the lock token (WAFOptimisticLockException); raise anything else.
        deadline = time.monotonic() + 120
        while True:
            try:
                current = wafv2.get_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=web_acl["Id"])
                wafv2.delete_web_acl(
                    Name=acl_name,
                    Scope="CLOUDFRONT",
                    Id=web_acl["Id"],
                    LockToken=current["LockToken"],
                )
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "WAFNonexistentItemException":
                    return
                if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                    raise
                if time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_acl)

    dist_id = _create_multitenant_distribution(ctx)

    domain_a = f"{ctx.unique_name('sim2real-cf-tenant-a-')}.sim2real.test"
    domain_b = f"{ctx.unique_name('sim2real-cf-tenant-b-')}.sim2real.test"

    tenant_with_acl = _create_tenant(
        ctx,
        dist_id,
        domain_a,
        customizations={"WebAcl": {"Action": "override", "Arn": web_acl_arn}},
    )
    tenant_without_acl = _create_tenant(ctx, dist_id, domain_b)

    cf = ctx.client("cloudfront")
    resp = cf.list_distribution_tenants_by_customization(WebACLArn=web_acl_arn)
    ids = {item["Id"] for item in resp["DistributionTenantList"]}

    assert tenant_with_acl["Id"] in ids, "tenant with matching WebACL customization missing from filtered list"
    assert tenant_without_acl["Id"] not in ids, "tenant without the customization leaked into the filtered list"


# ===== helpers =====
def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real multi-tenant test distribution",
            "Enabled": True,
            "ConnectionMode": "tenant-only",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "test-origin",
                        "DomainName": "www.example.com",
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "test-origin",
                "ViewerProtocolPolicy": "https-only",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
            "HttpVersion": "http2",
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        try:
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
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
    deadline = time.monotonic() + timeout_s
    etag = None
    last_status = None
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        last_status = got["Distribution"]["Status"]
        if last_status == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(15)
    if etag is None:
        raise AssertionError(
            f"distribution {dist_id} never reached Deployed within {timeout_s}s "
            f"(last status={last_status!r}) -- cleanup could not delete it"
        )
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_tenant(ctx, dist_id: str, domain: str, customizations: dict | None = None) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-tenant-")
    kwargs = {
        "DistributionId": dist_id,
        "Name": name,
        "Domains": [{"Domain": domain}],
        "Enabled": True,
        "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        # Real AWS rejects CreateDistributionTenant with InvalidArgument ("There must be at
        # least one certificate ... or a managed certificate request") unless one is present.
        # The domain is not a real, DNS-controlled name, so ValidationTokenHost="self-hosted"
        # is required: it defers domain-ownership verification and leaves the certificate
        # pending validation, whereas "cloudfront" demands synchronously that the domain
        # already resolve to a CloudFront resource and rejects the create outright. The create
        # call succeeding is all this check's CRUD-then-filter contract needs.
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
    }
    if customizations:
        kwargs["Customizations"] = customizations
    resp = cf.create_distribution_tenant(**kwargs)
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant["Id"]))
    return tenant


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = got["ETag"]
        if got["DistributionTenant"].get("Enabled"):
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
