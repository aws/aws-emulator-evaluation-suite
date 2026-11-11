"""verify-dns-configuration-mismatch-detected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-dns-configuration-mismatch-detected"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyDnsConfiguration reports unknown-configuration, with a Reason mentioning DNS, for a
    tenant domain that has no DNS record at all.
    """
    cf = ctx.client("cloudfront")

    dist_id = _create_multitenant_distribution(ctx)

    # A unique, unregistered .com label has no DNS record pointing anywhere, so
    # this domain never resolves -- i.e. it is guaranteed to have no DNS record at
    # all. (RFC 2606 reserved names like example.com are rejected outright by
    # CloudFront's managed-certificate domain validation, so we avoid them.)
    # invalid-configuration is reserved for a record that exists but points elsewhere.
    domain = f"{ctx.unique_name('sim2real-vdc-')}.com".lower()
    tenant = _create_distribution_tenant(ctx, dist_id, [domain], enabled=True)

    resp = cf.verify_dns_configuration(Domain=domain, Identifier=tenant["Id"])
    entries = resp.get("DnsConfigurationList", [])
    matches = [e for e in entries if e.get("Domain") == domain]
    assert matches, f"no DnsConfiguration entry for {domain!r} in {entries!r}"
    status = matches[0]["Status"]
    assert status == "unknown-configuration", (
        f"expected unknown-configuration for a domain with no DNS record, got {status!r}: {matches[0]!r}"
    )
    reason = matches[0].get("Reason", "")
    assert "DNS" in reason, f"expected Reason to mention DNS, got {reason!r}"


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-mtd-")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ref,
            "Comment": "sim2real-behav multi-tenant fixture",
            "Enabled": True,
            "ConnectionMode": "tenant-only",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "primary-origin",
                        "DomainName": "origin.example.com",
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "primary-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_fully(ctx, dist_id))
    return dist_id


def _delete_distribution_fully(ctx, dist_id: str, timeout_s: float = 240.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        dist = got["Distribution"]
        etag = got["ETag"]
        cfg = dist["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            try:
                cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
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
            time.sleep(3)
            continue
        if dist["Status"] == "Deployed":
            try:
                cf.delete_distribution(Id=dist_id, IfMatch=etag)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchDistribution":
                    raise
            return
        time.sleep(5)


def _create_distribution_tenant(
    ctx, dist_id: str, domains: list, enabled: bool = True, name: str | None = None
) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    name = name or ctx.unique_name("sim2real-behav-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": d} for d in domains],
        Enabled=enabled,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domains[0],
        },
    )
    tenant = resp["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant_fully(ctx, tenant_id))
    return tenant


def _delete_distribution_tenant_fully(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    tenant = got["DistributionTenant"]
    etag = got["ETag"]
    if tenant.get("Enabled"):
        try:
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        except ClientError:
            try:
                got = cf.get_distribution_tenant(Identifier=tenant_id)
                etag = got["ETag"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
                return
    try:
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
