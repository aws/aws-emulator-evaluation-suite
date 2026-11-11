"""list-distribution-tenants-pagination-consistent-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distribution-tenants-pagination-consistent-ordering"
GROUP = "ordering"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListDistributionTenants with a Marker yields a stable,
    non-overlapping, consistently ordered sequence across pages even as new
    tenants are created mid-pagination."""
    cf = ctx.client("cloudfront")
    primary_id = _create_primary_multitenant_distribution(ctx)
    ctx.on_cleanup(lambda: _delete_distribution(ctx, primary_id))

    tenant_ids = [_create_tenant(ctx, cf, primary_id, f"t{i}") for i in range(5)]

    # Baseline: one uninterrupted paginated sweep, MaxItems small enough to
    # force multiple pages.
    baseline_all = _paginate_all(cf)
    baseline_order = [tid for tid in baseline_all if tid in tenant_ids]
    assert sorted(baseline_order) == sorted(tenant_ids), (baseline_order, tenant_ids)
    assert len(baseline_order) == len(set(baseline_order)), "duplicate tenant across baseline pages"

    # Interrupted sweep: fetch page 1, create a new tenant mid-pagination,
    # then continue fetching the rest with the marker from page 1.
    resp1 = cf.list_distribution_tenants(MaxItems=2)
    page1_ids = [item["Id"] for item in resp1.get("DistributionTenantList", [])]
    marker = resp1.get("NextMarker")

    interloper_id = _create_tenant(ctx, cf, primary_id, "interloper")

    rest_ids: list[str] = []
    while marker:
        resp = cf.list_distribution_tenants(MaxItems=2, Marker=marker)
        rest_ids.extend(item["Id"] for item in resp.get("DistributionTenantList", []))
        marker = resp.get("NextMarker")

    interrupted_all = page1_ids + rest_ids
    interrupted_order = [tid for tid in interrupted_all if tid in tenant_ids]

    # The originally-tracked 5 tenants must each still appear exactly once,
    # in the same relative order as the uninterrupted baseline sweep -- the
    # interloper created mid-pagination must not duplicate or reorder them.
    assert interrupted_order == baseline_order, (interrupted_order, baseline_order)
    assert interrupted_all.count(interloper_id) <= 1, interrupted_all


def _paginate_all(cf, page_size: int = 2) -> list[str]:
    out: list[str] = []
    marker = None
    for _ in range(200):
        kwargs = {"MaxItems": page_size}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distribution_tenants(**kwargs)
        out.extend(item["Id"] for item in resp.get("DistributionTenantList", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return out


def _create_primary_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-dt-page-primary-"),
            "Comment": "sim2real behavioral: distribution tenant pagination ordering",
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
        }
    )
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    return resp["Distribution"]["Id"]


def _create_tenant(ctx, cf, primary_id: str, tag: str) -> str:
    domain = _domain_name(ctx, f"dt-page-{tag}")
    tenant = cf.create_distribution_tenant(
        DistributionId=primary_id,
        Name=ctx.unique_name(f"sim2real-cf-dt-page-{tag}-"),
        Domains=[{"Domain": domain}],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
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



def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


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
