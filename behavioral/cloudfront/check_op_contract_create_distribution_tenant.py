"""op-contract-create-distribution-tenant."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-distribution-tenant"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistributionTenant on a real multi-tenant distribution creates a tenant GetDistributionTenant
    reads back, while the same request with a nonexistent DistributionId is refused with EntityNotFound
    and the exact message and lists no tenant under that id."""

    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_distribution_tenant"):
        raise AssertionError("create_distribution_tenant not in installed botocore")

    origin_domain = f"{ctx.unique_name('sim2real-behav-cdt-origin')}.example.com"
    try:
        dist = cf.create_distribution(
            DistributionConfig={
                "CallerReference": ctx.unique_name("sim2real-behav-cdt-dist-"),
                "Comment": "sim2real behavioral check (multi-tenant primary)",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "primary-origin",
                            "DomainName": origin_domain,
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
                    "CachePolicyId": _MANAGED_CACHING_DISABLED_ID,
                },
            }
        )
    except ClientError as exc:
        raise AssertionError(
            f"unreachable: multi-tenant primary distribution unavailable in this "
            f"account: {exc.response['Error']['Code']}"
        ) from exc

    dist_id = dist["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(ctx, dist_id))

    # Positive control: the same call against the real DistributionId succeeds. Every tenant
    # needs a certificate; ValidationTokenHost="self-hosted" defers the domain-ownership check
    # that "cloudfront" makes at create time.
    good_name = ctx.unique_name("sim2real-behav-tenant-")[:64]
    good_domain = f"{good_name}.sim2real-behav-checks.click".lower()
    created = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=good_name,
        Domains=[{"Domain": good_domain}],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )
    tenant_id = created["DistributionTenant"]["Id"]

    def _cleanup_tenant(tenant_id=tenant_id):
        try:
            fresh = cf.get_distribution_tenant(Identifier=tenant_id)
            cf.delete_distribution_tenant(Id=tenant_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise

    ctx.on_cleanup(_cleanup_tenant)

    fetched = cf.get_distribution_tenant(Identifier=tenant_id)
    assert fetched["DistributionTenant"]["DistributionId"] == dist_id, (
        f"expected DistributionId {dist_id}, got {fetched['DistributionTenant']['DistributionId']}"
    )
    assert fetched["DistributionTenant"]["Domains"][0]["Domain"] == good_domain

    # Break exactly one thing: swap the real DistributionId for one that doesn't exist.
    # Keep the ManagedCertificateRequest identical to the positive call so the
    # certificate requirement can't be what's actually triggering the rejection.
    bad_name = ctx.unique_name("sim2real-behav-tenant-")[:64]
    bad_domain = f"{bad_name}.sim2real-behav-checks.click".lower()
    code, message = _error(
        lambda: cf.create_distribution_tenant(
            DistributionId="EDFDVBD6EXAMPLE",
            Name=bad_name,
            Domains=[{"Domain": bad_domain}],
            ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    expected = "The specified distribution does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent, on an independent read at the destination: nothing was created
    # under the nonexistent DistributionId.
    filtered = cf.list_distribution_tenants(
        AssociationFilter={"DistributionId": "EDFDVBD6EXAMPLE"}
    )
    assert filtered["DistributionTenantList"] == [], (
        f"rejected CreateDistributionTenant must not create a tenant, "
        f"got {filtered['DistributionTenantList']}"
    )


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    return None


def _cleanup_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        cfg = cfg_resp["DistributionConfig"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        etag = _wait_distribution_deployed(ctx, dist_id, timeout_s=900.0)
        if etag is None:
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
