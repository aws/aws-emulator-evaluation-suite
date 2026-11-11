"""associate-distribution-tenant-web-acl-limit-exceeded-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-distribution-tenant-web-acl-limit-exceeded-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _wafv2_client(ctx):
    """WAFv2 web ACLs with Scope=CLOUDFRONT can only be managed via the us-east-1 endpoint."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL with a different ARN replaces a tenant's existing web ACL
    instead of raising EntityLimitExceeded; reusing the superseded IfMatch fails with
    PreconditionFailed and its exact message, leaving the association and ETag unchanged."""
    cf = ctx.client("cloudfront")

    acl_1 = _create_web_acl(ctx)
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, acl_1["Name"], acl_1["Id"]))
    acl_2 = _create_web_acl(ctx)
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, acl_2["Name"], acl_2["Id"]))

    parent_id = _create_multitenant_distribution(ctx)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, parent_id))
    _wait_distribution_status(ctx, parent_id, "Deployed")

    domain_1 = f"{ctx.unique_name('sim2real-tw1-')}.sim2real-behav-checks.click"
    tenant = cf.create_distribution_tenant(
        DistributionId=parent_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain_1}],
        Enabled=False,
        Customizations={"WebAcl": {"Action": "override", "Arn": acl_1["ARN"]}},
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))

    created = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert created["Customizations"]["WebAcl"]["Arn"] == acl_1["ARN"], (
        f"expected tenant created with WebAcl override {acl_1['ARN']!r}, "
        f"got {created.get('Customizations')!r}"
    )
    stale_etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]

    # Positive control: associating a DIFFERENT web ACL on a tenant that already has one
    # succeeds and replaces it rather than raising EntityLimitExceeded.
    replaced = cf.associate_distribution_tenant_web_acl(
        Id=tenant_id, IfMatch=stale_etag, WebACLArn=acl_2["ARN"]
    )
    assert replaced["WebACLArn"] == acl_2["ARN"], (
        f"expected the association to persist {acl_2['ARN']!r}, got {replaced['WebACLArn']!r}"
    )
    fresh_etag = replaced["ETag"]
    assert fresh_etag != stale_etag

    after_replace = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert after_replace["Customizations"]["WebAcl"]["Arn"] == acl_2["ARN"], (
        f"expected the prior override ({acl_1['ARN']!r}) to be replaced by {acl_2['ARN']!r}, "
        f"got {after_replace['Customizations']}"
    )

    # Break exactly one thing: reuse the now-stale IfMatch for a second associate call.
    code, msg = _error(
        lambda: cf.associate_distribution_tenant_web_acl(
            Id=tenant_id, IfMatch=stale_etag, WebACLArn=acl_1["ARN"]
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    precondition_msg = "Your request is missing requirements for this operation. Update your request and try again."
    assert msg == precondition_msg, (
        f"expected message {precondition_msg!r}, got {msg!r}"
    )

    # effect absent: the stale-IfMatch rejection left the prior association and ETag untouched
    still = cf.get_distribution_tenant(Identifier=tenant_id)
    assert still["DistributionTenant"]["Customizations"]["WebAcl"]["Arn"] == acl_2["ARN"]
    assert still["ETag"] == fresh_etag

    # restore: the identical call with a fresh IfMatch now succeeds
    restored = cf.associate_distribution_tenant_web_acl(
        Id=tenant_id, IfMatch=fresh_etag, WebACLArn=acl_1["ARN"]
    )
    assert restored["WebACLArn"] == acl_1["ARN"]

    final = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert final["Customizations"]["WebAcl"]["Arn"] == acl_1["ARN"], (
        f"expected the restored call to persist {acl_1['ARN']!r}, got {final['Customizations']}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_web_acl(ctx):
    wafv2 = _wafv2_client(ctx)
    name = ctx.unique_name("sim2real-acl-")
    resp = wafv2.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
        Rules=[],
    )["Summary"]
    return resp


def _delete_web_acl(ctx, name, acl_id):
    wafv2 = _wafv2_client(ctx)
    try:
        lock_token = wafv2.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)["LockToken"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "WAFNonexistentItemException":
            return
        raise
    try:
        wafv2.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=lock_token)
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "WAFNonexistentItemException",
            "WAFAssociatedItemException",
        ):
            raise


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
