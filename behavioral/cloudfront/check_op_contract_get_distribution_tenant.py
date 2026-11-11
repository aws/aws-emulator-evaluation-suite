"""op-contract-get-distribution-tenant."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-distribution-tenant"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistributionTenant returns Status/Domains for a created tenant, 404s on unknown Identifier."""
    cf = ctx.client("cloudfront")

    # distinct error boundary is cheap and has no prerequisites: run it unconditionally.
    code, message = _error(lambda: cf.get_distribution_tenant(Identifier="sim2real-nonexistent-tenant"))
    assert code == "EntityNotFound", f"unexpected code {code}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    try:
        dist_id = _create_multitenant_distribution(ctx)
        domain = f"{ctx.unique_name('sim2real-tenant')}.sim2real-behavioral-test.com".replace("_", "-")
        created = cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-tenant-"),
            Domains=[{"Domain": domain}],
            ManagedCertificateRequest={
                "ValidationTokenHost": "self-hosted",
                "PrimaryDomainName": domain,
                "CertificateTransparencyLoggingPreference": "disabled",
            },
            Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
            Enabled=False,
        )
    except ClientError as exc:
        raise AssertionError(f"could not provision a distribution tenant in this environment: {exc}") from exc

    tenant_id = created["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))

    # success-path contract
    got = cf.get_distribution_tenant(Identifier=tenant_id)
    assert got["DistributionTenant"]["Id"] == tenant_id
    domains = [d["Domain"] for d in got["DistributionTenant"]["Domains"]]
    assert domain in domains
    assert "ETag" in got


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-mtorigin-')}.example.com"
    caller_ref = ctx.unique_name("sim2real-mtdist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real behavioral multi-tenant distribution",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cur = cf.get_distribution_tenant(Identifier=tenant_id)
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 600.0, interval_s: float = 20.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        etag = resp["ETag"]
        if resp["Distribution"]["Status"] == "Deployed":
            return etag
        time.sleep(interval_s)
    return etag


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            upd = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
            etag = upd["ETag"]
        etag = _wait_distribution_deployed(ctx, dist_id) or etag
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
