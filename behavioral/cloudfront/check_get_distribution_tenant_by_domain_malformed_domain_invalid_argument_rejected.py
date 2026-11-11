"""get-distribution-tenant-by-domain-malformed-domain-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-distribution-tenant-by-domain-malformed-domain-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistributionTenantByDomain answers a malformed domain string with the same EntityNotFound and
    message as an unbound domain (the model has no InvalidArgument case), and still answers it for the
    unvalidated domain of a real tenant that has reached Deployed."""
    cf = ctx.client("cloudfront")

    malformed_domain = "not a domain !! .. ///"
    code, message = _error(lambda: cf.get_distribution_tenant_by_domain(Domain=malformed_domain))
    assert code == "EntityNotFound", f"expected EntityNotFound (no InvalidArgument case exists), got {code!r}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    # Syntactically valid but never-associated domain fails with the identical code -- the
    # service does not distinguish "malformed" from "well-formed but unbound".
    never_associated = f"{ctx.unique_name('sim2real-neverassoc').lower()}.example.com"
    missing_code, missing_message = _error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=never_associated)
    )
    assert missing_code == "EntityNotFound", f"expected EntityNotFound, got {missing_code!r}"
    assert missing_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {missing_message!r}"
    )

    dist_id = _create_multi_tenant_distribution(ctx)
    real_domain = f"{ctx.unique_name('sim2real-realdom').lower()}.sim2real-cfbehav-test.com"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": real_domain}],
        Enabled=True,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "enabled",
            "PrimaryDomainName": real_domain,
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))

    # Positive control: the tenant reaches Deployed on an independent read (GetDistributionTenant
    # by ID, not the create response), so lookups do not simply 404 everything.
    deployed = _wait_tenant_deployed(ctx, tenant_id)
    assert deployed["Status"] == "Deployed", f"expected Deployed, got {deployed['Status']!r}"

    # Yet the SAME domain, on that SAME Deployed tenant, still 404s via domain-based lookup:
    # GetDistributionTenantByDomain needs the domain's certificate validated, which Deployed
    # status alone does not guarantee.
    still_missing, still_missing_message = _error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=real_domain)
    )
    assert still_missing == "EntityNotFound", (
        f"expected the unvalidated domain to still 404 on a Deployed tenant, got {still_missing!r}"
    )
    assert still_missing_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {still_missing_message!r}"
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


def _wait_tenant_deployed(ctx, tenant_id: str, timeout_s: float = 780.0, interval_s: float = 20.0) -> dict:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
        if last["Status"] == "Deployed":
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"tenant {tenant_id!r} never reached Deployed within {timeout_s}s (last status: "
        f"{last['Status'] if last else None!r})"
    )


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "get-distribution-tenant-by-domain malformed-domain negative check",
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
            "Tags": {"Items": [{"Key": "sim2real", "Value": "true"}]},
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
