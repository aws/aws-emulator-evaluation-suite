"""get-managed-certificate-details-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-managed-certificate-details-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetManagedCertificateDetails on an id that names no tenant returns EntityNotFound and the exact
    message, while on a real tenant that requested a managed certificate it returns an ACM ARN in
    pending-validation."""
    cf = ctx.client("cloudfront")

    fake_id = ctx.unique_name("nonexistent-tenant-")
    code, message = _error(lambda: cf.get_managed_certificate_details(Identifier=fake_id))
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    dist_id = _create_multi_tenant_distribution(ctx)
    # CloudFront refuses the reserved documentation roots (*.example.com and the like) with
    # InvalidArgument ("Domain Name not allowed"); a random unregistered .com name passes.
    domain = f"{ctx.unique_name('sim2real-mgdcert-').lower()}.com"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={
            # "cloudfront" requires the domain to resolve to CloudFront at creation time
            # (InvalidArgument "Could not verify Domain Name ownership"); "self-hosted" defers it.
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
            "CertificateTransparencyLoggingPreference": "enabled",
        },
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))

    # Positive control: a real tenant with a requested managed certificate is retrievable.
    got = cf.get_managed_certificate_details(Identifier=tenant_id)["ManagedCertificateDetails"]
    arn = got["CertificateArn"]
    assert arn.startswith("arn:aws:acm:"), f"expected an ACM certificate ARN, got {arn!r}"
    status = got["CertificateStatus"]
    assert status == "pending-validation", (
        f"expected a freshly requested, never-DNS-validated managed certificate to be "
        f"pending-validation, got {status!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "get-managed-certificate-details nonexistent negative check",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _disable_and_delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    etag = got["ETag"]
    if got["DistributionTenant"].get("Enabled"):
        disable_resp = cf.update_distribution_tenant(Id=tenant_id, Enabled=False, IfMatch=etag)
        etag = disable_resp["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = got["ETag"]
        if got["DistributionTenant"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
