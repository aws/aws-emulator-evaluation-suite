"""distribution-tenant-web-acl-association-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "distribution-tenant-web-acl-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating then disassociating an AWS WAF web ACL on a distribution tenant
    transitions its Customizations.WebAcl field through set-with-the-given-ARN then
    cleared, observed via GetDistributionTenant."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    cg_id = _create_connection_group(ctx)
    domain = f"{ctx.unique_name('sim2real-wacl-').strip('-')}.sim2real.test"
    tenant_id = _create_distribution_tenant(ctx, dist_id, domain, connection_group_id=cg_id, managed_cert=True)
    web_acl_arn = _create_cloudfront_web_acl(ctx)

    t0 = cf.get_distribution_tenant(Identifier=tenant_id)
    assert not (t0["DistributionTenant"].get("Customizations") or {}).get(
        "WebAcl"
    ), "freshly created tenant should not already have a web ACL association"
    etag = t0["ETag"]

    assoc = cf.associate_distribution_tenant_web_acl(
        Id=tenant_id, IfMatch=etag, WebACLArn=web_acl_arn
    )
    assert assoc["WebACLArn"] == web_acl_arn

    t1 = cf.get_distribution_tenant(Identifier=tenant_id)
    web_acl = (t1["DistributionTenant"].get("Customizations") or {}).get("WebAcl") or {}
    assert web_acl.get("Arn") == web_acl_arn, (
        f"expected Customizations.WebAcl.Arn to be set to {web_acl_arn!r}, got {web_acl!r}"
    )

    cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=t1["ETag"])

    t2 = cf.get_distribution_tenant(Identifier=tenant_id)
    web_acl_after = (t2["DistributionTenant"].get("Customizations") or {}).get("WebAcl")
    assert not (web_acl_after or {}).get("Arn"), (
        f"expected Customizations.WebAcl to be cleared after disassociation, got {web_acl_after!r}"
    )


def _create_multi_tenant_distribution(ctx, parameter_definitions=None):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant test distribution",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": parameter_definitions or []},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "example.com",
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
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id, timeout_s=1200, interval_s=15):
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dcfg = cfg["DistributionConfig"]
    if dcfg.get("Enabled"):
        dcfg["Enabled"] = False
        resp = cf.update_distribution(Id=dist_id, DistributionConfig=dcfg, IfMatch=etag)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed":
            etag = d["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_connection_group(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg_id


def _delete_connection_group(ctx, cg_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    g = cf.get_connection_group(Identifier=cg_id)
    etag = g["ETag"]
    if g["ConnectionGroup"].get("Enabled", True):
        resp = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        g = cf.get_connection_group(Identifier=cg_id)
        if g["ConnectionGroup"]["Status"] == "Deployed":
            etag = g["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


def _create_distribution_tenant(
    ctx, distribution_id, domain, connection_group_id=None, managed_cert=False, parameters=None
):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": name,
        "Domains": [{"Domain": domain}],
        "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    }
    if connection_group_id:
        kwargs["ConnectionGroupId"] = connection_group_id
    if managed_cert:
        # "cloudfront"-hosted validation makes CreateDistributionTenant synchronously verify
        # the domain already resolves to a CloudFront resource, which a domain nobody owns
        # never will. "self-hosted" defers that verification to whoever hosts the token, so
        # the call succeeds with the certificate left pending validation.
        kwargs["ManagedCertificateRequest"] = {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
        }
    if parameters:
        kwargs["Parameters"] = parameters
    resp = cf.create_distribution_tenant(**kwargs)
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant(ctx, tenant_id))
    return tenant_id


def _delete_distribution_tenant(ctx, tenant_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    t = cf.get_distribution_tenant(Identifier=tenant_id)
    etag = t["ETag"]
    if t["DistributionTenant"].get("Enabled", True):
        resp = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        t = cf.get_distribution_tenant(Identifier=tenant_id)
        if t["DistributionTenant"]["Status"] == "Deployed":
            etag = t["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _create_cloudfront_web_acl(ctx):
    # AWS WAF web ACLs with Scope=CLOUDFRONT are created against the us-east-1 wafv2 endpoint.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-tenant-waf-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    summary = resp["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, name, summary["Id"]))
    return summary["ARN"]


def _delete_web_acl(ctx, name, web_acl_id):
    waf = ctx.client("wafv2", region="us-east-1")
    g = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=g["LockToken"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
