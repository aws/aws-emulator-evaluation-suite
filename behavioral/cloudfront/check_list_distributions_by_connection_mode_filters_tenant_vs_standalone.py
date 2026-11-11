"""list-distributions-by-connection-mode-filters-tenant-vs-standalone."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-distributions-by-connection-mode-filters-tenant-vs-standalone"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


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


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_standard_distribution(ctx):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-std-"),
            "Comment": "sim2real behavioral check standard distribution",
            "Enabled": False,
            "ConnectionMode": "direct",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "primary-origin",
                        "DomainName": origin_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "primary-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _create_multi_tenant_distribution(ctx):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
            "Comment": "sim2real behavioral check multi-tenant distribution",
            "Enabled": False,
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
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _list_by_connection_mode(cf, mode):
    ids = set()
    marker = None
    while True:
        kwargs = {"ConnectionMode": mode, "MaxItems": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_connection_mode(**kwargs)
        dlist = resp["DistributionList"]
        ids.update(item["Id"] for item in dlist.get("Items", []))
        marker = dlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A standard ("direct") distribution and a multi-tenant ("tenant-only") distribution
    are correctly bucketed by ListDistributionsByConnectionMode: each appears only under
    its own connection mode."""
    cf = ctx.client("cloudfront")
    standard_id = _create_standard_distribution(ctx)
    tenant_only_id = _create_multi_tenant_distribution(ctx)

    direct_ids = _poll_until(
        lambda: _list_by_connection_mode(cf, "direct"),
        lambda ids: standard_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert standard_id in direct_ids, (
        f"standard distribution {standard_id} missing from ConnectionMode=direct: {direct_ids}"
    )
    assert tenant_only_id not in direct_ids, (
        f"tenant-only distribution {tenant_only_id} leaked into ConnectionMode=direct: {direct_ids}"
    )

    tenant_ids = _poll_until(
        lambda: _list_by_connection_mode(cf, "tenant-only"),
        lambda ids: tenant_only_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert tenant_only_id in tenant_ids, (
        f"tenant-only distribution {tenant_only_id} missing from ConnectionMode=tenant-only: {tenant_ids}"
    )
    assert standard_id not in tenant_ids, (
        f"standard distribution {standard_id} leaked into ConnectionMode=tenant-only: {tenant_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
