"""list-distribution-tenants-by-customization-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distribution-tenants-by-customization-filters-correctly"
GROUP = "data-plane"
SERVICES = ["cloudfront"]


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _create_multi_tenant_distribution(ctx):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
                "Comment": "sim2real behavioral check multi-tenant distribution",
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
                            "Id": "primary-origin",
                            "DomainName": origin_domain,
                            "OriginPath": "/{{tenantName}}",
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "primary-origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
                },
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    _wait_distribution_deployed(ctx, dist_id)
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    dist_config = cfg_resp["DistributionConfig"]
    dist_config["Enabled"] = False
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_distribution_tenant(ctx, tenant_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=resp["ETag"])


def _create_distribution_tenant(ctx, distribution_id, domain, **extra):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": domain}],
        "Enabled": False,
        "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        # Every distribution tenant needs at least one certificate; we don't own `domain`, so
        # ValidationTokenHost="self-hosted" lets CloudFront issue the managed cert without
        # requiring the domain's DNS to already CNAME to the connection group first (unlike
        # "cloudfront", which synchronously demands that and fails with InvalidArgument).
        "ManagedCertificateRequest": {"ValidationTokenHost": "self-hosted"},
    }
    kwargs.update(extra)
    resp = cf.create_distribution_tenant(**kwargs)
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda tid=tenant["Id"]: _delete_distribution_tenant(ctx, tid))
    return tenant


def _create_cloudfront_scoped_web_acl(ctx):
    """WAFv2 CLOUDFRONT-scope web ACLs are global but must be managed through the us-east-1
    endpoint (any other region answers WAFInvalidParameterException "The scope is not
    valid."). Pinned through ctx.client(..., region=) rather than aborting on ctx.region, so
    the same code path runs against every target -- an emulator keeps its shared endpoint."""
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-cf-webacl-")
    created = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", "")[:128] or "sim2realwebacl",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]
    arn = created["ARN"]
    web_acl_id = created["Id"]

    def _cleanup():
        current = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)
        waf.delete_web_acl(
            Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)
    return arn


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionTenantsByCustomization(WebACLArn=...) returns only the tenant overriding that web ACL."""
    web_acl_arn = _create_cloudfront_scoped_web_acl(ctx)
    dist_id = _create_multi_tenant_distribution(ctx)

    # RFC 2606 reserves "example.*"/"test"/"invalid"/"localhost" -- CloudFront rejects those as
    # tenant domains outright, so use an unreserved, obviously-synthetic parent domain instead.
    domain_with = f"{ctx.unique_name('sim2real-cf-waf')}.sim2real-behav-checks.click".replace("_", "-")
    domain_without = f"{ctx.unique_name('sim2real-cf-nowaf')}.sim2real-behav-checks.click".replace("_", "-")

    tenant_with = _create_distribution_tenant(
        ctx,
        dist_id,
        domain_with,
        Customizations={"WebAcl": {"Action": "override", "Arn": web_acl_arn}},
    )
    tenant_without = _create_distribution_tenant(ctx, dist_id, domain_without)

    cf = ctx.client("cloudfront")
    resp = cf.list_distribution_tenants_by_customization(WebACLArn=web_acl_arn)
    ids = {item["Id"] for item in resp.get("DistributionTenantList", [])}

    assert tenant_with["Id"] in ids, f"expected {tenant_with['Id']!r} in {ids!r}"
    assert tenant_without["Id"] not in ids, f"unrelated tenant {tenant_without['Id']!r} leaked into {ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
