"""op-contract-get-distribution-tenant-by-domain."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-distribution-tenant-by-domain"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistributionTenantByDomain answers EntityNotFound for an unassociated domain; CreateDistributionTenant
    answers EntityNotFound for an unknown DistributionId and InvalidArgument for a domain with no certificate path,
    each with its exact message, and the refused domain still resolves to no tenant."""
    cf = ctx.client("cloudfront")

    # distinct error boundary is cheap and has no prerequisites: run it unconditionally.
    code, message = _error(
        lambda: cf.get_distribution_tenant_by_domain(Domain="sim2real-nonexistent.example.com")
    )
    assert code == "EntityNotFound", f"unexpected code {code}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    dist_id = _create_multitenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-tenantdom')}.example.com".replace("_", "-")

    # Positive control on the same call shape: a bogus DistributionId is rejected with a
    # *different* specific code than the certificate boundary below -- proving CreateDistributionTenant
    # is reachable and discriminates its inputs, not just refusing every call identically.
    bogus_dist_code, bogus_dist_message = _error(
        lambda: cf.create_distribution_tenant(
            DistributionId="EDFDVBD6EXAMPLE",
            Name=ctx.unique_name("sim2real-bogusdist-"),
            Domains=[{"Domain": domain}],
        )
    )
    assert bogus_dist_code == "EntityNotFound", (
        f"expected EntityNotFound for a nonexistent DistributionId, got {bogus_dist_code!r}"
    )
    assert bogus_dist_message == "The specified distribution does not exist.", (
        f"expected AWS's exact message, got {bogus_dist_message!r}"
    )

    # The certificate boundary: a real multi-tenant distribution, a syntactically valid domain
    # this account cannot certify, no certificate path supplied.
    cert_code, cert_message = _error(
        lambda: cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-tenantdom-"),
            Domains=[{"Domain": domain}],
            Enabled=False,
        )
    )
    assert cert_code == "InvalidArgument", (
        f"expected InvalidArgument (no certificate path) for an uncertified domain, got {cert_code!r}"
    )
    assert cert_message == (
        "There must be at least one certificate in the distribution tenant or distribution, "
        "or there must be a managed certificate request"
    ), (
        f"expected AWS's exact message, got {cert_message!r}"
    )

    # Effect-absent: the rejected attempt created nothing -- the domain still resolves to nothing.
    post_attempt_code, post_attempt_message = _error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=domain)
    )
    assert post_attempt_code == "EntityNotFound", (
        f"expected EntityNotFound after a rejected tenant creation, got {post_attempt_code!r}"
    )
    assert post_attempt_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {post_attempt_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting what AWS refuses
    is a finding in itself, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-mtorigin-')}.example.com"
    caller_ref = ctx.unique_name("sim2real-mtdist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real behavioral multi-tenant distribution",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 600.0, interval_s: float = 20.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        etag = resp["ETag"]
        if resp["Distribution"]["Status"] == "Deployed":
            return etag
        time.sleep(interval_s)
    return etag


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            upd = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
            etag = upd["ETag"]
        etag = _wait_distribution_deployed(ctx, dist_id) or etag
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
