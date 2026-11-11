"""delete-distribution-tenant-stale-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "delete-distribution-tenant-stale-version-rejected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistributionTenant with an ETag superseded by a disabling update fails with
    PreconditionFailed and its exact message, and the tenant stays disabled at the newer ETag;
    deleting with the current ETag succeeds."""
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-mt-')}.s3.amazonaws.com"

    distribution_config = {
        "CallerReference": ctx.unique_name("sim2real-mtd-"),
        "Comment": "sim2real multi-tenant blueprint",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {
            "ParameterDefinitions": [
                {
                    "Name": "tenantName",
                    "Definition": {
                        "StringSchema": {
                            "Comment": "Tenant name",
                            "DefaultValue": "root",
                            "Required": False,
                        }
                    },
                }
            ]
        },
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "OriginPath": "/{{tenantName}}",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }

    try:
        created = cf.create_distribution(DistributionConfig=distribution_config)
    except (ClientError, ParamValidationError) as exc:
        raise AssertionError(
            "cannot create a multi-tenant (SaaS Manager) distribution in this "
            f"account/SDK vintage, required to provision a distribution tenant: {exc}"
        )

    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    # NOTE: CloudFront denylists *.example.com/.example.org/.example.net outright
    # with InvalidArgument ("Domain Name not allowed") since those roots are
    # IANA-reserved documentation domains; a random unregistered .com passes the
    # same format/denylist check without requiring real ownership or DNS control.
    domain1 = f"{ctx.unique_name('sim2real-tenant-')}.com"
    try:
        tenant = cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2realTenant"),
            Domains=[{"Domain": domain1}],
            ManagedCertificateRequest={
                "ValidationTokenHost": "self-hosted",
                "PrimaryDomainName": domain1,
            },
            Enabled=True,
        )
    except (ClientError, ParamValidationError) as exc:
        raise AssertionError(f"cannot create a distribution tenant in this account: {exc}")

    tenant_id = tenant["DistributionTenant"]["Id"]
    etag_t1 = tenant["ETag"]
    ctx.on_cleanup(lambda: _cleanup_tenant(cf, tenant_id))

    # Simulate a concurrent caller disabling the tenant, advancing its version.
    disable_resp = cf.update_distribution_tenant(
        Id=tenant_id, IfMatch=etag_t1, Domains=[{"Domain": domain1}], Enabled=False
    )
    etag_t2 = disable_resp["ETag"]
    assert etag_t2 != etag_t1

    # A caller still holding the pre-update etag tries to delete -> must be rejected.
    code, message = _error(lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag_t1))
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    assert message == "Your request is missing requirements for this operation. Update your request and try again.", f"unexpected PreconditionFailed message: {message!r}"

    # Effect absent: the tenant must still exist, disabled, at the winning version.
    current = cf.get_distribution_tenant(Identifier=tenant_id)
    assert current["DistributionTenant"]["Enabled"] is False
    assert current["ETag"] == etag_t2

    # Positive control: deleting with the current etag succeeds (tenant already disabled).
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag_t2)
    code_after, message_after = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert code_after == "EntityNotFound", f"expected deletion, got {code_after}"
    assert message_after == "The specified distribution tenant doesn't exist.", f"unexpected EntityNotFound message: {message_after!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _cleanup_tenant(cf, tenant_id):
    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    try:
        etag = current["ETag"]
        if current["DistributionTenant"].get("Enabled"):
            domains = current["DistributionTenant"]["Domains"]
            resp = cf.update_distribution_tenant(
                Id=tenant_id, IfMatch=etag, Domains=domains, Enabled=False
            )
            etag = resp["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


def _cleanup_distribution(cf, dist_id):
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    try:
        dconfig = cfg["DistributionConfig"]
        etag = cfg["ETag"]
        if dconfig.get("Enabled"):
            dconfig["Enabled"] = False
            upd = cf.update_distribution(DistributionConfig=dconfig, Id=dist_id, IfMatch=etag)
            etag = upd["ETag"]
        # CloudFront distribution changes propagate asynchronously; deletion requires
        # Status == Deployed. See "How CloudFront delivers content" in the developer guide.
        result = _poll_until(
            lambda: cf.get_distribution(Id=dist_id),
            lambda r: r["Distribution"]["Status"] == "Deployed",
            timeout_s=1200,
            interval_s=20,
        )
        cf.delete_distribution(Id=dist_id, IfMatch=result["ETag"])
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
