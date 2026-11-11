"""list-invalidations-for-distribution-tenant-ordering-most-recent-first."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invalidations-for-distribution-tenant-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvalidationsForDistributionTenant returns invalidations ordered
    most-recently-created first, matching the standard distribution
    invalidation ordering guarantee."""
    cf = ctx.client("cloudfront")
    primary_id = _create_primary_multitenant_distribution(ctx)
    ctx.on_cleanup(lambda: _delete_distribution(ctx, primary_id))

    tenant_id = _create_tenant(ctx, cf, primary_id)

    created_ids: list[str] = []
    for i in range(3):
        inv = _create_invalidation_with_retry(cf, tenant_id, i)
        created_ids.append(inv["Id"])
        # Ensure each invalidation gets a distinguishable CreateTime.
        time.sleep(2.0)

    # Poll the listing (bounded) until every created invalidation is visible in it.
    deadline = time.monotonic() + 120.0
    while True:
        listing = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)["InvalidationList"].get("Items", [])
        if set(created_ids) <= {item["Id"] for item in listing} or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    observed_ids = [item["Id"] for item in listing if item["Id"] in created_ids]
    assert set(observed_ids) == set(created_ids), (observed_ids, created_ids)

    # Most-recently-created first: reverse of creation order.
    assert observed_ids == list(reversed(created_ids)), (observed_ids, created_ids)


def _create_primary_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-cf-tenant-inv-primary-"),
                "Comment": "sim2real behavioral: tenant invalidation ordering",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "TenantConfig": {"ParameterDefinitions": []},
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "custom-origin",
                            "DomainName": "example.com",
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
                    "TargetOriginId": "custom-origin",
                    "ViewerProtocolPolicy": "redirect-to-https",
                    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # AWS managed CachingOptimized
                },
            },
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    return resp["Distribution"]["Id"]


def _create_tenant(ctx, cf, primary_id: str) -> str:
    domain = _domain_name(ctx, "tenant-inv")
    tenant = cf.create_distribution_tenant(
        DistributionId=primary_id,
        Name=ctx.unique_name("sim2real-cf-tenant-inv-"),
        Domains=[{"Domain": domain}],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id


def _domain_name(ctx, label: str) -> str:
    # NOTE: CloudFront rejects any *.example.com/.example.org/.example.net domain
    # outright with InvalidArgument ("Domain Name not allowed") -- those roots are
    # IANA-reserved documentation domains and CloudFront denylists them explicitly.
    # A random, unregistered .com name passes the same format/denylist check
    # without requiring us to actually own or DNS-validate it (CloudFront only
    # validates ownership later, via the pending managed-certificate TXT record).
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _create_invalidation_with_retry(cf, tenant_id: str, i: int, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cf.create_invalidation_for_distribution_tenant(
                Id=tenant_id,
                InvalidationBatch={
                    "Paths": {"Quantity": 1, "Items": [f"/order-test-{i}"]},
                    "CallerReference": f"sim2real-cf-tenant-inv-order-{i}-{tenant_id}"[:128],
                },
            )["Invalidation"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)



def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _wait_tenant_deployed(cf, tenant_id: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution tenant {tenant_id} never reached Deployed within {timeout_s}s")


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
        cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        config_resp = cf.get_distribution_config(Id=dist_id)
        config = config_resp["DistributionConfig"]
        etag = config_resp["ETag"]
        if config.get("Enabled"):
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
            _wait_distribution_deployed(cf, dist_id)
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
