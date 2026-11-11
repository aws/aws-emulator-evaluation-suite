"""update-distribution-tenant-cname-conflict-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-distribution-tenant-cname-conflict-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


def _domain_name(ctx, label: str) -> str:
    # CloudFront denylists *.example.com/.example.org/.example.net outright
    # (IANA-reserved documentation domains) with InvalidArgument "Domain Name not
    # allowed". A random, unregistered .com name passes that format check without
    # requiring us to own or DNS-validate it -- CloudFront defers ownership
    # validation to the pending managed-certificate TXT record, which is never
    # checked by CreateDistributionTenant/UpdateDistributionTenant themselves.
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _managed_cert_request(domain: str) -> dict:
    return {
        "ValidationTokenHost": "self-hosted",
        "CertificateTransparencyLoggingPreference": "disabled",
        "PrimaryDomainName": domain,
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDistributionTenant is NOT gated on another tenant's claim to the same domain while both are
    disabled and backed only by a pending managed certificate: tenant B's claim persists and tenant
    A keeps the domain too, and updating to a fresh unclaimed domain also succeeds.
    """
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    cg = _create_connection_group(ctx)

    domain_a = _domain_name(ctx, "tenanta")
    domain_b = _domain_name(ctx, "tenantb")
    domain_c = _domain_name(ctx, "tenantc")

    tenant_a_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-a-"),
        Domains=[{"Domain": domain_a}],
        ConnectionGroupId=cg["Id"],
        Enabled=False,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        ManagedCertificateRequest=_managed_cert_request(domain_a),
    )
    tenant_a_id = tenant_a_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_distribution_tenant(
        Id=tenant_a_id, IfMatch=cf.get_distribution_tenant(Identifier=tenant_a_id)["ETag"]
    ))

    tenant_b_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-b-"),
        Domains=[{"Domain": domain_b}],
        ConnectionGroupId=cg["Id"],
        Enabled=False,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        ManagedCertificateRequest=_managed_cert_request(domain_b),
    )
    tenant_b_id = tenant_b_resp["DistributionTenant"]["Id"]
    tenant_b_etag = tenant_b_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_distribution_tenant(
        Id=tenant_b_id, IfMatch=cf.get_distribution_tenant(Identifier=tenant_b_id)["ETag"]
    ))

    # The call under test: tenant B claims tenant A's domain. It is ACCEPTED.
    claimed = cf.update_distribution_tenant(
        Id=tenant_b_id, Domains=[{"Domain": domain_a}], IfMatch=tenant_b_etag,
        ManagedCertificateRequest=_managed_cert_request(domain_a),
    )
    claimed_domains = {d["Domain"] for d in claimed["DistributionTenant"]["Domains"]}
    assert claimed_domains == {domain_a}, (
        f"update response: expected tenant B to carry {domain_a!r}, got {claimed_domains!r}"
    )

    # The effect is PRESENT, read independently rather than off the update's echo.
    after = cf.get_distribution_tenant(Identifier=tenant_b_id)
    after_domains = {d["Domain"] for d in after["DistributionTenant"]["Domains"]}
    assert after_domains == {domain_a}, (
        f"independent read: expected tenant B to hold {domain_a!r}, got {after_domains!r}"
    )
    tenant_b_etag = after["ETag"]

    # ...and tenant A was not silently stripped of it: the same domain is claimed twice.
    tenant_a_after = cf.get_distribution_tenant(Identifier=tenant_a_id)
    tenant_a_domains = {d["Domain"] for d in tenant_a_after["DistributionTenant"]["Domains"]}
    assert domain_a in tenant_a_domains, (
        f"tenant A lost {domain_a!r} when tenant B claimed it, so the claim was moved rather "
        f"than duplicated: {tenant_a_domains!r}"
    )

    # Positive control: a fresh, unclaimed domain is accepted and persists too, so the
    # acceptance above is not this tenant being stuck accepting anything it is handed.
    fixed = cf.update_distribution_tenant(
        Id=tenant_b_id, Domains=[{"Domain": domain_c}], IfMatch=tenant_b_etag,
        ManagedCertificateRequest=_managed_cert_request(domain_c),
    )
    fixed_domains = {d["Domain"] for d in fixed["DistributionTenant"]["Domains"]}
    assert fixed_domains == {domain_c}, f"update response: expected {domain_c!r}, got {fixed_domains!r}"
    persisted = cf.get_distribution_tenant(Identifier=tenant_b_id)
    persisted_domains = {d["Domain"] for d in persisted["DistributionTenant"]["Domains"]}
    assert persisted_domains == {domain_c}, f"independent read: expected {domain_c!r}, got {persisted_domains!r}"


# ===== helpers =====

def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "tenant cname-conflict check",
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
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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
    # 900s: half of a heavy suite's 1800s per-check wall clock, so the teardown completes inside
    # the check's own ceiling.
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_connection_group(ctx) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name, Enabled=True, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    cg = resp["ConnectionGroup"]
    cg_id = cg["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(ctx, cg_id))
    return cg


def _disable_and_delete_connection_group(ctx, cg_id: str) -> None:
    cf = ctx.client("cloudfront")
    got = cf.get_connection_group(Identifier=cg_id)
    etag = got["ETag"]
    if got["ConnectionGroup"].get("Enabled"):
        etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
