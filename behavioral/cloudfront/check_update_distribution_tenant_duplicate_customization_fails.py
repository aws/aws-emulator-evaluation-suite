"""update-distribution-tenant-duplicate-customization-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-distribution-tenant-duplicate-customization-fails"
GROUP = "representation"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDistributionTenant with a Domains list that repeats the tenant's own domain succeeds and the tenant then
    lists that domain once; a further update adding a distinct second domain lists both."""
    cf = ctx.client("cloudfront")

    parent_id = _create_multitenant_distribution(ctx)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, parent_id))
    _wait_distribution_status(ctx, parent_id, "Deployed")

    domain_1 = f"{ctx.unique_name('sim2real-d1-')}.sim2real-behav-checks.click"
    tenant = cf.create_distribution_tenant(
        DistributionId=parent_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain_1}],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))

    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.update_distribution_tenant(
        Id=tenant_id,
        IfMatch=etag,
        Domains=[{"Domain": domain_1}, {"Domain": domain_1}],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )

    # independent read: the repeated entry deduplicated, not doubled
    still = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    still_domains = [d["Domain"] for d in still["Domains"]]
    assert still_domains == [domain_1], f"expected deduplicated domains {[domain_1]}, got {still_domains}"

    # positive control: adding a second, distinct domain succeeds
    domain_2 = f"{ctx.unique_name('sim2real-d2-')}.sim2real-behav-checks.click"
    etag2 = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.update_distribution_tenant(
        Id=tenant_id,
        IfMatch=etag2,
        Domains=[{"Domain": domain_1}, {"Domain": domain_2}],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )
    updated = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    updated_domains = sorted(d["Domain"] for d in updated["Domains"])
    expected_domains = sorted([domain_1, domain_2])
    assert updated_domains == expected_domains, f"expected domains {expected_domains}, got {updated_domains}"


def _min_multitenant_distribution_config(ctx):
    origin_id = "sim2real-origin"
    return {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Origins": {
            "Quantity": 1,
            "Items": [{
                "Id": origin_id,
                "DomainName": "www.example.com",
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only",
                },
            }],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "Comment": "sim2real behavioral check (multi-tenant)",
        "Enabled": True,
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
    }


def _create_multitenant_distribution(ctx):
    cf = ctx.client("cloudfront")
    cfg = _min_multitenant_distribution_config(ctx)
    dist = cf.create_distribution(DistributionConfig=cfg)["Distribution"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
    return dist["Id"]


def _wait_distribution_status(ctx, dist_id, target_status, timeout_s=1500.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last = resp["Distribution"]["Status"]
        if last == target_status:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"Distribution {dist_id} never reached {target_status} (last={last})")


def _disable_and_delete_distribution(ctx, dist_id, timeout_s=1500.0):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_distribution_status(ctx, dist_id, "Deployed", timeout_s=timeout_s)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _disable_and_delete_tenant(ctx, tenant_id, timeout_s=900.0, interval_s=10.0):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    tenant = resp["DistributionTenant"]
    etag = resp["ETag"]
    if tenant.get("Enabled"):
        etag = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)["ETag"]
    deadline = time.monotonic() + timeout_s
    status = tenant.get("Status")
    while status != "Deployed" and time.monotonic() < deadline:
        time.sleep(interval_s)
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
        status = resp["DistributionTenant"]["Status"]
        etag = resp["ETag"]
    try:
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
