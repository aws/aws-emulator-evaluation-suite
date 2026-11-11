"""distribution-tenant-delete-stale-etag-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-tenant-delete-stale-etag-rejected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_PRECONDITION_FAILED = (
    "Your request is missing requirements for this operation. Update your request and try again."
)
_TENANT_NOT_FOUND = "The specified distribution tenant doesn't exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistributionTenant with a stale IfMatch ETag is rejected with
    PreconditionFailed, leaves the tenant intact, and the same delete with the
    current ETag succeeds."""
    cf = ctx.client("cloudfront")

    dist_id = _create_multitenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-dts-')}.com".lower()
    tenant = _create_distribution_tenant(ctx, dist_id, [domain], enabled=False)
    tenant_id = tenant["Id"]

    stale_etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]

    # Bump the tenant's version by performing a no-op update.
    updated = cf.update_distribution_tenant(Id=tenant_id, IfMatch=stale_etag, Enabled=False)
    current_etag = updated["ETag"]
    assert current_etag != stale_etag, "expected the update to advance the ETag"

    code, message = _error(
        lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=stale_etag)
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}"
    assert message == _PRECONDITION_FAILED, f"expected message {_PRECONDITION_FAILED!r}, got {message!r}"

    # Effect absent: the tenant still exists.
    still_there = cf.get_distribution_tenant(Identifier=tenant_id)
    assert still_there["DistributionTenant"]["Id"] == tenant_id, (
        f"expected tenant {tenant_id!r} to survive the rejected delete, "
        f"got {still_there['DistributionTenant']['Id']!r}"
    )

    # Positive control: deleting with the current ETag succeeds.
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=current_etag)
    code_after, message_after = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert code_after == "EntityNotFound", f"expected EntityNotFound, got {code_after!r}"
    assert message_after == _TENANT_NOT_FOUND, f"expected message {_TENANT_NOT_FOUND!r}, got {message_after!r}"


def _error(fn):
    """Run fn and return the ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
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
