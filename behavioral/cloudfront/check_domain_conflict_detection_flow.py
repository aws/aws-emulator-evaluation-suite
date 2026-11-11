"""domain-conflict-detection-flow."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

_NO_CERTIFICATE = (
    "There must be at least one certificate in the distribution tenant or distribution, or there "
    "must be a managed certificate request"
)
CHECK = "domain-conflict-detection-flow"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainConflicts refuses (InvalidArgument) a tenant holding only a pending managed
    certificate request, and a second tenant claiming the identical domain is accepted.

    Reference: https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDomainConflicts.html
    """
    cf = ctx.client("cloudfront")

    # Positive control first: this account can author real CloudFront resources, so every
    # refusal below is about the domain claim and not about permissions or setup.
    dist_id = _create_multitenant_distribution(ctx)

    domain = f"{ctx.unique_name('sim2real-dcf-')}.com".lower()
    tenant1 = _create_distribution_tenant(ctx, dist_id, [domain], enabled=False)
    holder = cf.get_distribution_tenant(Identifier=tenant1["Id"])["DistributionTenant"]
    assert domain in [d["Domain"] for d in holder["Domains"]], (
        f"tenant {tenant1['Id']} does not list the domain it was created with: {holder!r}"
    )

    # ListDomainConflicts cannot be used to discover that claim.
    code, message = _error_code_and_message(
        lambda: cf.list_domain_conflicts(
            Domain=domain,
            DomainControlValidationResource={"DistributionTenantId": tenant1["Id"]},
        )
    )
    assert code == "InvalidArgument", (
        f"expected InvalidArgument from ListDomainConflicts against a tenant holding only a "
        f"pending managed certificate request, got {code!r} ({message!r})"
    )
    assert message == _NO_CERTIFICATE, (
        f"expected the refusal {_NO_CERTIFICATE!r}, got {message!r}"
    )

    # An unvalidated domain claim is not enforced: a second tenant under the same multi-tenant
    # distribution claiming the IDENTICAL domain is accepted.
    tenant2 = _create_distribution_tenant(ctx, dist_id, [domain], enabled=False)
    assert tenant2["Id"] != tenant1["Id"]
    assert [d["Domain"] for d in tenant2["Domains"]] == [domain], (
        f"second tenant's create response does not carry {domain!r}: {tenant2['Domains']!r}"
    )

    # Read both back independently: the same domain is now claimed twice.
    for tid in (tenant1["Id"], tenant2["Id"]):
        got = cf.get_distribution_tenant(Identifier=tid)["DistributionTenant"]
        assert domain in [d["Domain"] for d in got["Domains"]], (
            f"tenant {tid} no longer lists {domain!r} after the duplicate claim: {got!r}"
        )


def _error_code_and_message(fn):
    """Call fn(); return (code, message). Raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to be refused, but it succeeded: {resp!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-mtd-")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
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
            },
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
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
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
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
