"""create-and-update-distribution-tenant-invalid-web-acl-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-and-update-distribution-tenant-invalid-web-acl-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_INVALID_WEBACL = (
    "InvalidArgument",
    "The specified web ACL isn't valid. Specify a web ACL that was previously validated and try again.",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistributionTenant and UpdateDistributionTenant reject a Customizations.WebAcl
    override naming a nonexistent CLOUDFRONT-scope web ACL or a real REGIONAL-scope one; no
    tenant is created, and an existing tenant keeps its prior web ACL customization."""
    cf = ctx.client("cloudfront")

    # Web ACLs are created first so their cleanup runs last (LIFO), after the tenant's and the
    # distribution's: WAFv2 refuses to delete a web ACL a CloudFront resource still references.
    regional_acl_arn = _create_web_acl(ctx, "REGIONAL")
    cf_acl_arn = _create_web_acl(ctx, "CLOUDFRONT")
    other_cf_acl_arn = _create_web_acl(ctx, "CLOUDFRONT")

    dist_id = _create_multi_tenant_distribution(ctx)

    nonexistent_cf_arn = (
        f"arn:aws:wafv2:us-east-1:{ctx.account}:global/webacl/"
        f"{ctx.unique_name('sim2real-missing-')}/00000000-0000-0000-0000-000000000000"
    )

    # Break one thing: a nonexistent but well-formed CLOUDFRONT-scope ARN.
    _expect_error(
        lambda: cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-cdt-missing-"),
            Domains=[{"Domain": _domain(ctx, "cdt-missing")}],
            Enabled=False,
            Customizations={"WebAcl": {"Action": "override", "Arn": nonexistent_cf_arn}},
            ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        ),
        *_INVALID_WEBACL,
    )

    # Break one thing a different way: a real ARN, but the wrong scope.
    _expect_error(
        lambda: cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-cdt-regional-"),
            Domains=[{"Domain": _domain(ctx, "cdt-regional")}],
            Enabled=False,
            Customizations={"WebAcl": {"Action": "override", "Arn": regional_acl_arn}},
            ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        ),
        *_INVALID_WEBACL,
    )

    # Effect absent: neither rejected CreateDistributionTenant call left a tenant behind. The
    # filter is this check's own freshly minted DistributionId, so the list is exact.
    listed = cf.list_distribution_tenants(AssociationFilter={"DistributionId": dist_id})
    assert listed["DistributionTenantList"] == [], (
        f"a rejected CreateDistributionTenant must not create a tenant, got "
        f"{listed['DistributionTenantList']!r}"
    )

    # Positive control: the same request with a real CLOUDFRONT-scope web ACL succeeds. This is
    # also the baseline tenant that UpdateDistributionTenant is tested against below.
    tenant = _create_tenant(ctx, dist_id, "cdt-ok", cf_acl_arn)
    tenant_id = tenant["Id"]
    web_acl = tenant["Customizations"]["WebAcl"]
    assert web_acl["Arn"] == cf_acl_arn, f"expected Customizations.WebAcl.Arn {cf_acl_arn!r}, got {web_acl!r}"
    assert web_acl["Action"] == "override", f"expected Action 'override', got {web_acl['Action']!r}"

    listed_after = cf.list_distribution_tenants(AssociationFilter={"DistributionId": dist_id})
    listed_ids = [t["Id"] for t in listed_after["DistributionTenantList"]]
    assert listed_ids == [tenant_id], f"expected only {tenant_id!r} listed, got {listed_ids!r}"

    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]

    # UpdateDistributionTenant: break the same two ways, against the existing tenant.
    _expect_error(
        lambda: cf.update_distribution_tenant(
            Id=tenant_id,
            IfMatch=etag,
            Customizations={"WebAcl": {"Action": "override", "Arn": nonexistent_cf_arn}},
        ),
        *_INVALID_WEBACL,
    )

    after_1 = cf.get_distribution_tenant(Identifier=tenant_id)
    assert after_1["ETag"] == etag, f"tenant version changed despite the rejected update, got {after_1['ETag']!r}"
    web_acl_1 = after_1["DistributionTenant"]["Customizations"]["WebAcl"]
    assert web_acl_1["Arn"] == cf_acl_arn, (
        f"expected the tenant to keep its prior web ACL {cf_acl_arn!r} after the rejected update, "
        f"got {web_acl_1!r}"
    )

    _expect_error(
        lambda: cf.update_distribution_tenant(
            Id=tenant_id,
            IfMatch=etag,
            Customizations={"WebAcl": {"Action": "override", "Arn": regional_acl_arn}},
        ),
        *_INVALID_WEBACL,
    )

    after_2 = cf.get_distribution_tenant(Identifier=tenant_id)
    assert after_2["ETag"] == etag, f"tenant version changed despite the rejected update, got {after_2['ETag']!r}"
    web_acl_2 = after_2["DistributionTenant"]["Customizations"]["WebAcl"]
    assert web_acl_2["Arn"] == cf_acl_arn, (
        f"expected the tenant to keep its prior web ACL {cf_acl_arn!r} after the rejected update, "
        f"got {web_acl_2!r}"
    )

    # Positive control for the update path: swapping in a different real CLOUDFRONT-scope web
    # ACL succeeds and replaces the customization.
    updated = cf.update_distribution_tenant(
        Id=tenant_id,
        IfMatch=etag,
        Customizations={"WebAcl": {"Action": "override", "Arn": other_cf_acl_arn}},
    )["DistributionTenant"]
    assert updated["Customizations"]["WebAcl"]["Arn"] == other_cf_acl_arn, (
        f"expected UpdateDistributionTenant to accept a valid web ACL, got "
        f"{updated['Customizations']['WebAcl']!r}"
    )


def _expect_error(fn, expected_code: str, expected_message: str) -> None:
    """Call fn(); assert it fails with exactly (expected_code, expected_message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message")
        assert code == expected_code, f"expected {expected_code!r}, got {code!r} ({message!r})"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
        return
    raise AssertionError(f"expected the call to be refused with {expected_code!r}, but it succeeded with {result!r}")


def _domain(ctx, label: str) -> str:
    return f"{ctx.unique_name(f'sim2real-{label}-')}.test".lower()


def _multi_tenant_origin_config() -> dict:
    return {
        "Id": "origin1",
        "DomainName": "www.example.com",
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real create-and-update-distribution-tenant-invalid-web-acl-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [_multi_tenant_origin_config()]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id


def _create_tenant(ctx, dist_id: str, label: str, web_acl_arn: str) -> dict:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name(f"sim2real-{label}-"),
        Domains=[{"Domain": _domain(ctx, label)}],
        Enabled=False,
        Customizations={"WebAcl": {"Action": "override", "Arn": web_acl_arn}},
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant["Id"]))
    return tenant


def _delete_tenant(ctx, tenant_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        config = cfg_resp["DistributionConfig"]
        etag = cfg_resp["ETag"]
        if config.get("Enabled"):
            config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
        resp = _wait_distribution_deployed(ctx, dist_id)
        cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


def _create_web_acl(ctx, scope: str) -> str:
    waf = ctx.client("wafv2", region="us-east-1") if scope == "CLOUDFRONT" else ctx.client("wafv2")
    name = ctx.unique_name(f"sim2real-cf-acl-{scope.lower()}-")
    resp = waf.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
    )
    summary = resp["Summary"]
    web_acl_id, arn = summary["Id"], summary["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, scope, name, web_acl_id))
    return arn


def _delete_web_acl(ctx, scope: str, name: str, web_acl_id: str) -> None:
    from botocore.exceptions import ClientError

    waf = ctx.client("wafv2", region="us-east-1") if scope == "CLOUDFRONT" else ctx.client("wafv2")
    deadline = time.monotonic() + 300
    while True:
        try:
            lock_token = waf.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"]
            waf.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=lock_token)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
