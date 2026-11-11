"""managed-certificate-details-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-certificate-details-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedCertificateDetails returns EntityNotFound for an id that never named a tenant.

    The same call on a real tenant that requested a managed certificate returns its certificate ARN.
    """
    cf = ctx.client("cloudfront")

    fake_id = ctx.unique_name("dt-sim2real-bogus-")
    code, message = _error(lambda: cf.get_managed_certificate_details(Identifier=fake_id))
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    expected = "The specified distribution tenant doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    dist_id = _create_multitenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-cf-tenant-')}.sim2real-behav-checks.click"
    tenant = _create_tenant(ctx, dist_id, domain)

    # A tenant must have some certificate, and a non-managed one needs a DNS-validated
    # custom domain, so the negative case uses a never-created identifier instead.
    details = cf.get_managed_certificate_details(Identifier=tenant["Id"])["ManagedCertificateDetails"]
    assert details["CertificateArn"].startswith("arn:aws"), (
        f"expected a real certificate ARN for tenant {tenant['Id']!r}, "
        f"got {details.get('CertificateArn')!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real multi-tenant test distribution",
            "Enabled": True,
            "ConnectionMode": "tenant-only",
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "test-origin",
                        "DomainName": "www.example.com",
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
                "TargetOriginId": "test-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        try:
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
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
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if got["Distribution"]["Status"] == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(15)
    if etag is None:
        return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _create_tenant(ctx, dist_id: str, domain: str) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        # self-hosted validation lets CloudFront issue the managed cert without requiring
        # the domain's DNS to already CNAME to the connection group first (unlike
        # ValidationTokenHost="cloudfront", which synchronously demands that).
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant["Id"]))
    return tenant


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = got["ETag"]
        if got["DistributionTenant"].get("Enabled"):
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
