"""list-distribution-tenants-reflects-created-tenants."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distribution-tenants-reflects-created-tenants"
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
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    _wait_distribution_deployed(ctx, dist_id)
    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    etag = config_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
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
        "ManagedCertificateRequest": {"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    }
    kwargs.update(extra)
    resp = cf.create_distribution_tenant(**kwargs)
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda tid=tenant["Id"]: _delete_distribution_tenant(ctx, tid))
    return tenant


def _list_tenant_ids_for_distribution(cf, dist_id, max_items):
    """Walk ListDistributionTenants with a small page size, returning (ids, page_count)."""
    ids: list[str] = []
    marker = None
    pages = 0
    while True:
        kwargs = {"AssociationFilter": {"DistributionId": dist_id}, "MaxItems": max_items}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distribution_tenants(**kwargs)
        pages += 1
        ids.extend(item["Id"] for item in resp.get("DistributionTenantList", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return ids, pages


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Several created distribution tenants are all enumerated by ListDistributionTenants, with correct pagination."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)

    created_ids = set()
    for i in range(3):
        raw = ctx.unique_name(f"sim2real-cf-t{i}-").lower()
        domain = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-") + ".com"
        tenant = _create_distribution_tenant(ctx, dist_id, domain)
        created_ids.add(tenant["Id"])

    # Page through with MaxItems=2 (< 3 created) to exercise NextMarker/Marker.
    ids, pages = _list_tenant_ids_for_distribution(cf, dist_id, max_items=2)

    assert pages >= 2, f"expected pagination across at least 2 pages, got {pages}"
    assert len(ids) == len(set(ids)), f"tenant ids repeated across pages: {ids}"
    assert set(ids) == created_ids, f"expected exactly {created_ids}, got {set(ids)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
