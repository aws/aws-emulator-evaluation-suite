"""disassociate-tenant-web-acl-when-none-associated-invalid-argument."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "disassociate-tenant-web-acl-when-none-associated-invalid-argument"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionTenantWebACL with no web ACL associated is an idempotent no-op, not
    InvalidArgument; an associated web ACL disassociates and a read shows it cleared."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_id, etag = _create_disabled_tenant(ctx, dist_id)

    pre = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert pre.get("Customizations", {}).get("WebAcl") is None, (
        f"expected a freshly created tenant to have no WebAcl customization, got {pre.get('Customizations')!r}"
    )

    # Idempotent no-op: disassociating when nothing is associated succeeds, not InvalidArgument.
    noop = cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=etag)
    assert noop is not None, "expected a response from disassociate_distribution_tenant_web_acl"

    # Independent read at the destination: still no WebAcl customization.
    after = cf.get_distribution_tenant(Identifier=tenant_id)
    assert after["DistributionTenant"].get("Customizations", {}).get("WebAcl") is None, (
        f"expected no WebAcl customization after a no-op disassociate, got {after['DistributionTenant'].get('Customizations')!r}"
    )
    etag = after["ETag"]

    # Positive control: associate then disassociate a real web ACL, both succeed.
    web_acl_arn = _create_web_acl(ctx)
    assoc = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=web_acl_arn, IfMatch=etag)
    etag = assoc["ETag"]

    # Independent read at the destination: the association actually took effect.
    associated = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert associated.get("Customizations", {}).get("WebAcl", {}).get("Arn") == web_acl_arn, (
        f"expected WebAcl {web_acl_arn!r} associated, got {associated.get('Customizations')!r}"
    )

    disassoc = cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=etag)
    assert disassoc is not None, "expected a response from disassociate_distribution_tenant_web_acl"

    # Terminal read: independent of the mutating call, confirms the web ACL is actually gone.
    cleared = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert cleared.get("Customizations", {}).get("WebAcl") is None, (
        f"expected no WebAcl customization after disassociate, got {cleared.get('Customizations')!r}"
    )


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real disassociate-tenant-web-acl-when-none-associated-invalid-argument",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
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
            ],
        },
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


def _create_disabled_tenant(ctx, dist_id: str):
    cf = ctx.client("cloudfront")
    # CloudFront denylists *.example.com/.example.org/.example.net (IANA-reserved
    # documentation domains) with InvalidArgument; a random unregistered .com passes
    # the same format check without needing DNS ownership (validated later, async,
    # via the pending managed-certificate request).
    raw = ctx.unique_name("sim2real-cf-tenant-").lower()
    domain = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-") + ".com"
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        # AWS requires either a Certificate or a ManagedCertificateRequest on every tenant;
        # self-hosted avoids needing the fake domain's DNS to actually point at CloudFront.
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id, resp["ETag"]


def _delete_tenant(ctx, tenant_id: str, timeout_s: float = 900.0, interval_s: float = 10.0) -> None:
    import time

    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    while time.monotonic() < deadline:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
        if current["DistributionTenant"]["Status"] == "Deployed":
            etag = current["ETag"]
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"tenant {tenant_id} never reached Deployed within {timeout_s}s")
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    import time

    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _create_web_acl(ctx) -> str:
    # Scope="CLOUDFRONT" web ACLs must be managed via the us-east-1 endpoint; any other
    # region rejects them with WAFInvalidParameterException.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-cf-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]
    arn = summary["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, name, web_acl_id))
    return arn


def _delete_web_acl(ctx, name: str, web_acl_id: str) -> None:
    waf = ctx.client("wafv2", region="us-east-1")
    lock_token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
    waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
