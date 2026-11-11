"""distribution-tenant-invalidation-status-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "distribution-tenant-invalidation-status-transitions"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution-tenant invalidation reads InProgress or Completed on its create response, Get
    and List right after creation, and a bounded poll observes it reach Completed on both APIs.
    """
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    cg = _create_connection_group(ctx)
    # CloudFront rejects the IANA example.* documentation domains, and ValidationTokenHost=
    # "cloudfront" needs a domain already resolving to CloudFront; a random .com with "self-hosted"
    # passes format checks and defers ownership proof to the pending certificate.
    domain = f"{ctx.unique_name('sim2real-tenant-').lower()}.com"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain}],
        ConnectionGroupId=cg["Id"],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant(ctx, tenant_id))

    batch = {
        "Paths": {"Quantity": 1, "Items": ["/sim2real-status-transition/one"]},
        "CallerReference": ctx.unique_name("sim2real-invalidation-status-"),
    }
    create_resp = cf.create_invalidation_for_distribution_tenant(Id=tenant_id, InvalidationBatch=batch)
    invalidation_id = create_resp["Invalidation"]["Id"]

    # Right after creation the invalidation reads InProgress or, once the batch is finished,
    # Completed: CloudFront documents no InProgress duration.
    assert create_resp["Invalidation"]["Status"] in ("InProgress", "Completed"), (
        f"expected a freshly created invalidation to read InProgress or Completed, got "
        f"{create_resp['Invalidation']['Status']!r}"
    )
    fresh_get = cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=invalidation_id)
    assert fresh_get["Invalidation"]["Id"] == invalidation_id, (
        f"GetInvalidationForDistributionTenant returned id {fresh_get['Invalidation']['Id']!r}, "
        f"expected {invalidation_id!r}"
    )
    assert fresh_get["Invalidation"]["Status"] in ("InProgress", "Completed"), (
        f"expected GetInvalidationForDistributionTenant to read InProgress or Completed right "
        f"after creation, got {fresh_get['Invalidation']['Status']!r}"
    )
    fresh_list = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    fresh_summary = _find_invalidation(fresh_list, invalidation_id)
    assert fresh_summary is not None, (
        f"expected invalidation {invalidation_id!r} in ListInvalidationsForDistributionTenant "
        f"right after creation, got none matching"
    )
    assert fresh_summary["Status"] in ("InProgress", "Completed"), (
        f"expected ListInvalidationsForDistributionTenant to read InProgress or Completed right "
        f"after creation, got {fresh_summary['Status']!r}"
    )

    # Bounded poll for the transition to Completed on both read APIs.
    completed_get = _poll_until(
        lambda: cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=invalidation_id),
        lambda r: r["Invalidation"]["Status"] == "Completed",
        timeout_s=1200,
        interval_s=15,
        description=f"GetInvalidationForDistributionTenant({invalidation_id}) to reach Completed",
    )
    assert completed_get["Invalidation"]["Status"] == "Completed", (
        f"expected GetInvalidationForDistributionTenant to settle on Completed, got "
        f"{completed_get['Invalidation']['Status']!r}"
    )

    completed_list = _poll_until(
        lambda: cf.list_invalidations_for_distribution_tenant(Id=tenant_id),
        lambda r: (_find_invalidation(r, invalidation_id) or {}).get("Status") == "Completed",
        timeout_s=600,
        interval_s=15,
        description=f"ListInvalidationsForDistributionTenant to show {invalidation_id} as Completed",
    )
    completed_summary = _find_invalidation(completed_list, invalidation_id)
    assert completed_summary is not None, (
        f"expected invalidation {invalidation_id!r} still present in "
        f"ListInvalidationsForDistributionTenant once Completed, got none matching"
    )
    assert completed_summary["Status"] == "Completed", (
        f"expected ListInvalidationsForDistributionTenant to settle on Completed, got "
        f"{completed_summary['Status']!r}"
    )



def _find_invalidation(list_resp, invalidation_id):
    for item in list_resp.get("InvalidationList", {}).get("Items", []):
        if item.get("Id") == invalidation_id:
            return item
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description} (last observed: {value!r})"
    )


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "tenant invalidation status-transition check",
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


def _create_connection_group(ctx) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name, Enabled=True, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    cg = resp["ConnectionGroup"]
    cg_id = cg["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg


def _delete_distribution_tenant(ctx, tenant_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    t = cf.get_distribution_tenant(Identifier=tenant_id)
    etag = t["ETag"]
    if t["DistributionTenant"].get("Enabled", True):
        etag = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        t = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = t["ETag"]
        if t["DistributionTenant"]["Status"] == "Deployed":
            break
        time.sleep(interval_s)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _delete_connection_group(ctx, cg_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    g = cf.get_connection_group(Identifier=cg_id)
    etag = g["ETag"]
    if g["ConnectionGroup"].get("Enabled", True):
        etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        g = cf.get_connection_group(Identifier=cg_id)
        etag = g["ETag"]
        if g["ConnectionGroup"]["Status"] == "Deployed":
            break
        time.sleep(interval_s)
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
