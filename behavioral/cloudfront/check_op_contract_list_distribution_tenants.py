"""op-contract-listDistributionTenants."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listDistributionTenants"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionTenants lists a just-created tenant, an AssociationFilter on its DistributionId returns
    exactly that tenant, and a filter on a DistributionId no tenant has returns an empty list, not an error."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-cf-lt-')}.com"
    tenant_id = _create_tenant(ctx, dist_id, domain)

    resp = cf.list_distribution_tenants()
    assert "DistributionTenantList" in resp, f"missing DistributionTenantList in {resp!r}"
    all_ids = [item["Id"] for item in resp["DistributionTenantList"]]
    assert tenant_id in all_ids, f"expected freshly created tenant {tenant_id!r} in {all_ids!r}"

    matching = cf.list_distribution_tenants(AssociationFilter={"DistributionId": dist_id})
    matching_ids = [item["Id"] for item in matching["DistributionTenantList"]]
    assert matching_ids == [tenant_id], (
        f"filtering by the tenant's own DistributionId should return exactly that "
        f"tenant {tenant_id!r}, got {matching_ids!r}"
    )

    try:
        filtered = cf.list_distribution_tenants(
            AssociationFilter={"DistributionId": "EBOGUSDISTRIBUTIONID"}
        )
    except ClientError as exc:
        raise AssertionError(
            f"filtering by a DistributionId with no matching tenant should yield an "
            f"empty list, not an error; got {exc.response['Error']['Code']}"
        )
    assert filtered["DistributionTenantList"] == [], (
        f"filtering by a DistributionId with no matching tenant should yield an "
        f"empty list, not an error; got {filtered['DistributionTenantList']!r}"
    )


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real op-contract-listDistributionTenants",
        # CreateDistributionTenant rejects a disabled parent with InvalidAssociation
        # ("The specified multi-tenant distribution is disabled").
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
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _create_tenant(ctx, dist_id: str, domain: str) -> str:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        # Every distribution tenant needs at least one certificate; "self-hosted" defers the
        # domain-ownership proof, and the check only needs the tenant to exist.
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _delete_distribution(ctx, dist_id: str) -> None:
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
