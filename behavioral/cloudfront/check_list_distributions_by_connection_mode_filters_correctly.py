"""list-distributions-by-connection-mode-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-connection-mode-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByConnectionMode lists a standard distribution only under "direct" and a
    multi-tenant distribution only under "tenant-only"."""
    cf = ctx.client("cloudfront")

    direct_id = _create_direct_distribution(ctx)
    tenant_only_id = _create_tenant_only_distribution(ctx)

    direct_ids = _poll_until_present(
        lambda: _collect_all_ids(cf.list_distributions_by_connection_mode, ConnectionMode="direct"),
        direct_id,
    )
    assert direct_id in direct_ids, "the direct distribution is missing from the direct partition"
    assert tenant_only_id not in direct_ids, "the tenant-only distribution leaked into the direct partition"

    tenant_only_ids = _poll_until_present(
        lambda: _collect_all_ids(cf.list_distributions_by_connection_mode, ConnectionMode="tenant-only"),
        tenant_only_id,
    )
    assert tenant_only_id in tenant_only_ids, "the tenant-only distribution is missing from its partition"
    assert direct_id not in tenant_only_ids, "the direct distribution leaked into the tenant-only partition"


def _poll_until_present(probe, expected_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> set[str]:
    deadline = time.monotonic() + timeout_s
    ids: set[str] = set()
    while time.monotonic() < deadline:
        ids = probe()
        if expected_id in ids:
            return ids
        time.sleep(interval_s)
    raise AssertionError(
        f"{expected_id} never appeared in ListDistributionsByConnectionMode within {timeout_s}s "
        f"(last seen: {ids!r})"
    )


def _collect_all_ids(list_fn, **kwargs) -> set[str]:
    ids: set[str] = set()
    marker = None
    while True:
        params = dict(kwargs)
        params["MaxItems"] = 100
        if marker:
            params["Marker"] = marker
        resp = list_fn(**params)
        body = resp["DistributionList"]
        for item in body.get("Items", []):
            ids.add(item["Id"])
        if not body.get("IsTruncated"):
            break
        marker = body.get("NextMarker")
        if not marker:
            break
    return ids


def _create_direct_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-direct-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "connection-mode filter check (direct)",
        "Enabled": False,
        "ConnectionMode": "direct",
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


def _create_tenant_only_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-tenantonly-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "connection-mode filter check (tenant-only)",
        "Enabled": False,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
