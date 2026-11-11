"""distribution-tenant-web-acl-association-toggles-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "distribution-tenant-web-acl-association-toggles-state"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL attaches an ACL visible on GetDistributionTenant, and
    DisassociateDistributionTenantWebACL removes it, reflected on the next read."""
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_name = ctx.unique_name("sim2real-tenant-")
    # CloudFront denylists *.example.{com,org,net} (RFC 2606 reserved) outright with
    # InvalidArgument; an unregistered-but-non-reserved domain clears that check without
    # needing real DNS ownership (ValidationTokenHost="self-hosted" defers validation).
    domain = f"{ctx.unique_name('sim2real-tenant-').lower()}.com"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    etag = tenant_resp["ETag"]
    assert "WebAcl" not in tenant_resp["DistributionTenant"].get("Customizations", {}), (
        f"freshly created tenant should have no WebAcl customization, "
        f"got {tenant_resp['DistributionTenant'].get('Customizations')!r}"
    )
    ctx.on_cleanup(lambda: cf.delete_distribution_tenant(
        Id=tenant_id, IfMatch=cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    ))

    web_acl_arn = _create_cloudfront_web_acl(ctx)

    assoc = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=web_acl_arn, IfMatch=etag)
    etag = assoc["ETag"]

    after_assoc = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    web_acl_after_assoc = after_assoc.get("Customizations", {}).get("WebAcl")
    assert web_acl_after_assoc is not None and web_acl_after_assoc["Arn"] == web_acl_arn, (
        f"expected Customizations.WebAcl.Arn == {web_acl_arn!r} after association, "
        f"got {web_acl_after_assoc!r}"
    )
    assert web_acl_after_assoc["Action"] == "override", (
        f"expected Customizations.WebAcl.Action == 'override', got {web_acl_after_assoc['Action']!r}"
    )

    disassoc = cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=etag)
    etag = disassoc["ETag"]

    after_disassoc = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    web_acl_after_disassoc = after_disassoc.get("Customizations", {}).get("WebAcl")
    assert not web_acl_after_disassoc, (
        f"expected Customizations.WebAcl to be cleared after disassociation, "
        f"got {web_acl_after_disassoc!r}"
    )


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "tenant webacl toggle check",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_cloudfront_web_acl(ctx) -> str:
    # WAF web ACLs with Scope=CLOUDFRONT are managed only from the us-east-1 endpoint,
    # regardless of where the distribution/tenant itself lives.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", "")[:128],
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    summary = resp["Summary"]
    acl_id = summary["Id"]
    arn = summary["ARN"]

    def _cleanup():
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
        waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
