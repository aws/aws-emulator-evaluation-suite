"""verify-dns-configuration-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "verify-dns-configuration-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VerifyDnsConfiguration given a malformed domain name fails with InvalidArgument and its exact message;
    verifying the tenant's own domain succeeds and returns that domain with a non-empty status."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    # RFC 2606 reserved names like example.com are rejected outright by CreateDistributionTenant
    # ("The request contains an invalid domain name"), so use a unique .com label instead.
    domain = f"{ctx.unique_name('sim2real-cf-verify-')}.com"
    tenant_id = _create_tenant(ctx, dist_id, domain, enabled=False)

    malformed_domain = "not a valid domain!! ###"
    code, message = _error_code(lambda: cf.verify_dns_configuration(Domain=malformed_domain, Identifier=tenant_id))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "The specified domain name isn't associated with the distribution tenant. Specify another domain name and try again.", (
        f"expected the exact InvalidArgument message AWS returns, got {message!r}"
    )

    # Positive control: a well-formed, real domain of this tenant returns a real DNS status.
    ok = cf.verify_dns_configuration(Domain=domain, Identifier=tenant_id)
    entries = ok["DnsConfigurationList"]
    assert len(entries) >= 1, f"expected at least one DnsConfigurationList entry, got {entries!r}"
    assert entries[0]["Domain"] == domain, f"expected Domain {domain!r}, got {entries[0].get('Domain')!r}"
    assert entries[0]["Status"], f"expected a non-empty Status, got {entries[0].get('Status')!r}"


def _error_code(fn):
    """(code, message) of the ClientError fn() raises; a success raises, since accepting the call is a finding."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _multi_tenant_origin_config() -> dict:
    return {
        "Id": "origin1",
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


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real verify-dns-configuration-invalid-argument-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [_multi_tenant_origin_config()]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id


def _create_tenant(ctx, dist_id: str, domain: str, enabled: bool):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    # The domain is attached with a self-hosted-validation managed certificate request, which
    # needs no DNS control; the tenant then carries the domain VerifyDnsConfiguration inspects.
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=enabled,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))

    return tenant_id


def _delete_tenant(ctx, tenant_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

