"""update-distribution-tenant-cname-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-distribution-tenant-cname-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployed tenant whose domain has only a pending managed certificate does not hold it: UpdateDistributionTenant
    moving a second tenant onto that domain succeeds (no CNAMEAlreadyExists), both tenants then list it, and an
    update to a unique domain succeeds and persists."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)

    domain1 = f"{ctx.unique_name('sim2real-cf-tenant1-')}.com".lower()
    domain2 = f"{ctx.unique_name('sim2real-cf-tenant2-')}.com".lower()
    tenant1_id, _tenant1_etag = _create_disabled_tenant(ctx, dist_id, domain1, enabled=True)
    tenant2_id, tenant2_etag = _create_disabled_tenant(ctx, dist_id, domain2)

    # tenant1 has finished deploying domain1 before tenant2 claims it.
    _wait_tenant_deployed(ctx, tenant1_id)

    claimed = cf.update_distribution_tenant(
        Id=tenant2_id,
        Domains=[{"Domain": domain1}],
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain1,
        },
        IfMatch=tenant2_etag,
    )
    tenant2_etag = claimed["ETag"]

    after = cf.get_distribution_tenant(Identifier=tenant2_id)
    domains = [d["Domain"] for d in after["DistributionTenant"]["Domains"]]
    assert domains == [domain1], f"expected tenant2 to own {domain1!r} after the claim, got {domains!r}"
    holder = cf.get_distribution_tenant(Identifier=tenant1_id)
    holder_domains = [d["Domain"] for d in holder["DistributionTenant"]["Domains"]]
    assert holder_domains == [domain1], f"expected tenant1 to keep {domain1!r}, got {holder_domains!r}"

    # Positive control: a genuinely unique domain updates successfully.
    domain3 = f"{ctx.unique_name('sim2real-cf-tenant3-')}.com".lower()
    ok = cf.update_distribution_tenant(
        Id=tenant2_id,
        Domains=[{"Domain": domain3}],
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain3,
        },
        IfMatch=tenant2_etag,
    )
    ok_domains = [d["Domain"] for d in ok["DistributionTenant"]["Domains"]]
    assert ok_domains == [domain3], f"expected the update response to reflect {domain3!r}, got {ok_domains!r}"

    # Terminal read: independent of the mutating call, at the destination.
    final = cf.get_distribution_tenant(Identifier=tenant2_id)
    final_domains = [d["Domain"] for d in final["DistributionTenant"]["Domains"]]
    assert final_domains == [domain3], (
        f"expected an independent read to show {domain3!r} persisted, got {final_domains!r}"
    )


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
        "Comment": "sim2real update-distribution-tenant-cname-conflict-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
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


def _create_disabled_tenant(ctx, dist_id: str, domain: str, enabled: bool = False):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=enabled,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id, resp["ETag"]


def _delete_tenant(ctx, tenant_id: str, timeout_s: float = 900.0) -> None:
    """DeleteDistributionTenant requires a disabled tenant (ResourceNotDisabled otherwise), so an
    enabled tenant is disabled and allowed to finish deploying first; then wait until it is gone,
    since the distribution cannot be deleted while it still has tenants."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    gone = ("EntityNotFound", "NoSuchDistributionTenant", "NoSuchResource")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in gone:
            return
        raise
    if got["DistributionTenant"].get("Enabled"):
        cf.update_distribution_tenant(Id=tenant_id, Enabled=False, IfMatch=got["ETag"])
    _wait_tenant_deployed(ctx, tenant_id, timeout_s=timeout_s)
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            cf.get_distribution_tenant(Identifier=tenant_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in gone:
                return
            raise
        time.sleep(15)
    raise AssertionError(f"distribution tenant {tenant_id} still exists {timeout_s}s after its delete")


def _wait_tenant_deployed(ctx, tenant_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
        if resp["DistributionTenant"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution tenant {tenant_id} never reached Deployed within {timeout_s}s")


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
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
