"""op-contract-createInvalidationForDistributionTenant."""
from __future__ import annotations

import random
import string

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createInvalidationForDistributionTenant"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _bogus_tenant_id() -> str:
    # Distribution-tenant Ids are their own undocumented space -- "dt_" followed by an opaque
    # base62-looking token (e.g. "dt_3JO1OQa51Jb3BZh7XQh6pbvF3Wa"), not the 13-15 char
    # uppercase-alphanumeric distribution-Id shape and not a UUID (AWS rejects both with
    # InvalidArgument("Id format is invalid") ahead of the not-found lookup). Matching the shape
    # makes the lookup answer EntityNotFound.
    alphabet = string.ascii_letters + string.digits
    return "dt_" + "".join(random.choices(alphabet, k=27))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvalidationForDistributionTenant on a well-formed but unknown tenant id is refused with
    EntityNotFound and the exact message, while on a real tenant it creates an invalidation that
    GetInvalidationForDistributionTenant returns, InProgress or Completed."""
    cf = ctx.client("cloudfront")

    bogus_id = _bogus_tenant_id()
    code, message = _error(
        lambda: cf.create_invalidation_for_distribution_tenant(
            Id=bogus_id,
            InvalidationBatch={
                "CallerReference": ctx.unique_name("sim2real-tenant-inval-"),
                "Paths": {"Quantity": 1, "Items": ["/*"]},
            },
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}: {message}"
    expected = "The specified distribution tenant doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Success path: a real tenant with a self-hosted managed-certificate request, which defers the
    # domain-ownership check "cloudfront" makes at create time. Reserved names (*.example.com) are
    # refused as "Domain Name not allowed" either way, so the domain is an unreserved one.
    dist_id = _create_multi_tenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-tenant')}.sim2real-cftest.net"
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-")[:64],
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )
    tenant = resp["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))

    inval = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_id,
        InvalidationBatch={
            "CallerReference": ctx.unique_name("sim2real-tenant-inval-ok-"),
            "Paths": {"Quantity": 1, "Items": ["/*"]},
        },
    )["Invalidation"]
    assert inval["Id"]
    assert inval["Status"] in ("InProgress", "Completed")

    # Independent read at the destination (not the mutating call's own response): the
    # invalidation must be visible via GetInvalidationForDistributionTenant too.
    got = cf.get_invalidation_for_distribution_tenant(
        DistributionTenantId=tenant_id, Id=inval["Id"]
    )["Invalidation"]
    assert got["Id"] == inval["Id"]
    assert got["Status"] in ("InProgress", "Completed")


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-mtdist-")
    origin_domain = f"{ctx.unique_name('origin')}.example.com"
    config = {
        "CallerReference": ref,
        "Comment": "sim2real behavioral check (multi-tenant)",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "ConnectionMode": "tenant-only",
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    return dist_id


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _delete_distribution_best_effort(ctx, dist_id: str) -> None:
    import time

    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        dist_config = cfg_resp["DistributionConfig"]
        if dist_config.get("Enabled"):
            dist_config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=dist_config)["ETag"]
        deadline = time.monotonic() + 180
        status = None
        while time.monotonic() < deadline:
            info = cf.get_distribution(Id=dist_id)
            status = info["Distribution"]["Status"]
            etag = info["ETag"]
            if status == "Deployed":
                break
            time.sleep(10)
        if status == "Deployed":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
