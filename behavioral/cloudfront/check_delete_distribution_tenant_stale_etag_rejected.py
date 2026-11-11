"""delete-distribution-tenant-stale-etag-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-distribution-tenant-stale-etag-rejected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistributionTenant with the creation-time ETag, after an update disabled the tenant,
    fails with PreconditionFailed and its exact message and leaves the tenant disabled; deleting
    with the current ETag succeeds."""
    cf = ctx.client("cloudfront")
    primary_id = _create_primary_multitenant_distribution(ctx)
    ctx.on_cleanup(lambda: _delete_distribution(ctx, primary_id))

    domain = _domain_name(ctx, "dt-etag")
    created = cf.create_distribution_tenant(
        DistributionId=primary_id,
        Name=ctx.unique_name("sim2real-cf-dt-etag-"),
        Domains=[{"Domain": domain}],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Enabled=True,
    )
    tenant_id = created["DistributionTenant"]["Id"]
    etag0 = created["ETag"]
    ctx.on_cleanup(lambda: _best_effort_delete_tenant(ctx, tenant_id))
    assert created["DistributionTenant"]["Enabled"] is True, (
        f"expected a newly created tenant to be Enabled, got {created['DistributionTenant']['Enabled']!r}"
    )

    # Bump the version (and disable, which we'll need for the eventual real
    # delete anyway) using the correct precondition.
    updated = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag0, Enabled=False)
    etag1 = updated["ETag"]
    assert etag1 != etag0, f"expected the ETag to advance past {etag0!r} after update, got {etag1!r}"
    assert updated["DistributionTenant"]["Enabled"] is False, (
        f"expected Enabled=False after the disabling update, got {updated['DistributionTenant']['Enabled']!r}"
    )

    # Break exactly one thing: delete using the now-stale ETag from creation time.
    code, message = _error(lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag0))
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale IfMatch, got {code!r}"
    assert message == "Your request is missing requirements for this operation. Update your request and try again.", f"unexpected PreconditionFailed message: {message!r}"

    # Effect absent: the tenant still exists, still reflecting the disabled
    # state from the intervening update (not deleted).
    still = cf.get_distribution_tenant(Identifier=tenant_id)
    assert still["DistributionTenant"]["Id"] == tenant_id, (
        f"expected the tenant to still exist as {tenant_id!r}, got {still['DistributionTenant']['Id']!r}"
    )
    assert still["DistributionTenant"]["Enabled"] is False, (
        "expected the rejected delete to leave the tenant's state from the intervening update "
        f"(Enabled=False) untouched, got {still['DistributionTenant']['Enabled']!r}"
    )

    # Positive control: delete with the current ETag succeeds.
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=still["ETag"])
    code_after, message_after = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert code_after == "EntityNotFound", (
        f"expected the tenant deleted with a fresh IfMatch to read back EntityNotFound, got {code_after!r}"
    )
    assert message_after == "The specified distribution tenant doesn't exist.", f"unexpected EntityNotFound message: {message_after!r}"


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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_primary_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-dt-etag-primary-"),
            "Comment": "sim2real behavioral: distribution tenant etag concurrency",
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
    return resp["Distribution"]["Id"]


def _wait_distribution_deployed(cf, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cf.get_distribution(Id=dist_id)["Distribution"]["Status"] == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


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


def _best_effort_delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        get_resp = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    try:
        etag = get_resp["ETag"]
        if get_resp["DistributionTenant"].get("Enabled"):
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
