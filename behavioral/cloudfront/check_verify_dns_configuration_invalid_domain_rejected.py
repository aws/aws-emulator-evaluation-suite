"""verify-dns-configuration-invalid-domain-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "verify-dns-configuration-invalid-domain-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyDnsConfiguration on a distribution tenant rejects a malformed domain with InvalidArgument
    and its exact message, while the tenant's own valid domain returns a DnsConfigurationList entry."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multitenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-verifydns-').lower()}.sim2real-behav-checks.click"
    tenant_id = _create_tenant(ctx, dist_id, domain)

    malformed_domain = "not a domain !! .. ///"
    code, message = _error(lambda: cf.verify_dns_configuration(
        Identifier=tenant_id, Domain=malformed_domain
    ))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected_message = "The specified domain name isn't associated with the distribution tenant. Specify another domain name and try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a syntactically valid domain succeeds and is echoed back.
    ok = cf.verify_dns_configuration(Identifier=tenant_id, Domain=domain)
    entries = ok["DnsConfigurationList"]
    assert len(entries) >= 1, f"expected at least one DNS configuration entry, got {entries!r}"
    assert any(e["Domain"] == domain for e in entries), f"expected an entry for {domain!r} in {entries!r}"

    # Disable -> Deployed -> delete takes minutes, so tear down here and confirm the distribution
    # is gone; the on_cleanup registration is an idempotent safety net for the failure path.
    _teardown(ctx, tenant_id, dist_id)
    assert not _distribution_exists(ctx, dist_id), f"distribution {dist_id} still exists after delete"


# ===== helpers =====

def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real verify-dns-configuration-invalid-domain-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
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
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_OPTIMIZED_POLICY_ID,
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown(ctx, None, dist_id))
    return dist_id


def _create_tenant(ctx, dist_id: str, domain: str) -> str:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted"},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id


def _delete_tenant(ctx, tenant_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _distribution_exists(ctx, dist_id: str) -> bool:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        cf.get_distribution(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return False
        raise
    return True


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")
        time.sleep(interval_s)


def _teardown(ctx, tenant_id, dist_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    if tenant_id is not None:
        _delete_tenant(ctx, tenant_id)
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
