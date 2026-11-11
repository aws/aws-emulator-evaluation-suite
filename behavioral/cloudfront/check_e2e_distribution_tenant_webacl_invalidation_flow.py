"""e2e-distribution-tenant-webacl-invalidation-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-distribution-tenant-webacl-invalidation-flow"
GROUP = "e2e"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tenant + WAF web ACL association + tenant-scoped invalidation reaches Completed, then teardown."""
    # AssociateDistributionTenantWebACL requires a real WAFv2 web ACL with Scope=CLOUDFRONT,
    # which can only be created against the us-east-1 endpoint.
    cf = ctx.client("cloudfront")
    waf = ctx.client("wafv2", region="us-east-1")

    acl_name = ctx.unique_name("sim2real-cf-acl-")
    created_acl = waf.create_web_acl(
        Name=acl_name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": acl_name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    acl_id = created_acl["Id"]
    acl_arn = created_acl["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(waf, acl_name, acl_id))

    dist_id, _ = _create_distribution(ctx, cf, connection_mode="tenant-only", enabled=True)
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    tenant_name = ctx.unique_name("sim2real-cf-tenant-")
    # RFC 2606 reserves "example.*" — CloudFront rejects it outright as a tenant domain. Use
    # self-hosted validation so CreateDistributionTenant doesn't synchronously demand the
    # domain's DNS already CNAME to the connection group (which a throwaway domain can't satisfy).
    domain = f"{tenant_name}.sim2real-behav-checks.click"
    created = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = created["DistributionTenant"]["Id"]
    tenant_etag = created["ETag"]
    ctx.on_cleanup(lambda: _cleanup_tenant(cf, tenant_id))

    assoc = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=acl_arn, IfMatch=tenant_etag)
    assert assoc["WebACLArn"] == acl_arn, (
        f"expected AssociateDistributionTenantWebACL to echo {acl_arn}, got {assoc['WebACLArn']}"
    )

    refreshed = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    web_acl_customization = refreshed.get("Customizations", {}).get("WebAcl", {})
    assert web_acl_customization.get("Arn") == acl_arn, (
        f"expected GetDistributionTenant Customizations.WebAcl.Arn={acl_arn}, got {web_acl_customization.get('Arn')}"
    )
    assert web_acl_customization.get("Action") == "override", (
        f"expected Customizations.WebAcl.Action='override', got {web_acl_customization.get('Action')}"
    )

    inv = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/*"]},
            "CallerReference": ctx.unique_name("sim2real-cf-inv-"),
        },
    )["Invalidation"]

    final = _poll_invalidation_completed(cf, tenant_id, inv["Id"])
    assert final["Status"] == "Completed", f"expected tenant-scoped invalidation Status='Completed', got {final['Status']!r}"

    # Tear down synchronously, in-body: a tenant/distribution disable + wait-for-Deployed +
    # delete can exceed ctx.on_cleanup's 60s budget (DEFAULT_CLEANUP_TIMEOUT_S), which would
    # abandon it on a daemon thread and leak a tagged-but-enabled resource. The on_cleanup
    # registrations above remain as a best-effort safety net for an early-exit path (e.g. an
    # assertion failing before this point); calling them again here is idempotent.
    _cleanup_tenant(cf, tenant_id)
    _delete_web_acl(waf, acl_name, acl_id)
    _cleanup_distribution(cf, dist_id)


def _create_distribution(ctx, cf, *, connection_mode=None, enabled):
    bucket_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.amazonaws.com"
    cfg = {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": "sim2real behavioral check",
        "Enabled": enabled,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": bucket_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
    }
    if connection_mode:
        cfg["ConnectionMode"] = connection_mode
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist = resp["Distribution"]
    return dist["Id"], dist["ARN"]


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_distribution(cf, dist_id):
    from botocore.exceptions import ClientError

    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        etag = updated["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _wait_tenant_deployed(cf, tenant_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"tenant {tenant_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_tenant(cf, tenant_id):
    from botocore.exceptions import ClientError

    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    tenant = current["DistributionTenant"]
    etag = current["ETag"]
    if tenant.get("Enabled"):
        updated = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
        etag = updated["ETag"]
    _wait_tenant_deployed(cf, tenant_id)
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _poll_invalidation_completed(cf, tenant_id, inv_id, timeout_s=240, interval_s=8):

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=inv_id)[
            "Invalidation"
        ]
        if last["Status"] == "Completed":
            return last
        time.sleep(interval_s)
    status = last["Status"] if last else None
    raise AssertionError(f"invalidation {inv_id} did not complete within {timeout_s}s (last status={status})")


def _delete_web_acl(waf, name, acl_id):
    from botocore.exceptions import ClientError

    try:
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
            return
        raise
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
