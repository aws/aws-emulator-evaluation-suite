"""op-contract-associate-distribution-tenant-web-acl."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-associate-distribution-tenant-web-acl"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL on a deleted tenant's Id is rejected with EntityNotFound.

    Tenant Ids carry a format check ahead of the lookup, so the Id comes from a real tenant that
    is created and deleted first."""

    cf = ctx.client("cloudfront")
    if not hasattr(cf, "associate_distribution_tenant_web_acl"):
        raise AssertionError("associate_distribution_tenant_web_acl not in installed botocore")

    dist_id = _create_multitenant_distribution(ctx)
    tenant_id, etag = _mint_dead_tenant_id(ctx, dist_id)

    bogus_acl_arn = (
        f"arn:aws:wafv2:us-east-1:{ctx.account}:global/webacl/"
        "sim2real-nonexistent/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error(
        lambda: cf.associate_distribution_tenant_web_acl(
            Id=tenant_id, IfMatch=etag, WebACLArn=bogus_acl_arn
        )
    )
    if code == "UnsupportedOperation":
        raise AssertionError("multi-tenant distributions not enabled on this account")
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    expected = "The specified distribution tenant doesn't exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the tenant we deleted is still gone.
    gone_code, gone_message = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert gone_code == "EntityNotFound", f"expected deleted tenant to read EntityNotFound, got {gone_code}"
    expected = "The specified distribution tenant doesn't exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    # Tear the distribution down in-body; the on_cleanup registration is an idempotent backstop
    # for an early exit (e.g. an assertion failing before this line).
    _delete_distribution(ctx, dist_id)


# ===== helpers =====
def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-origin"
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-optc-mt-"),
        "Comment": "sim2real op-contract-associate-distribution-tenant-web-acl",
        "Enabled": True,  # CreateDistributionTenant rejects a disabled multi-tenant distribution
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # AWS managed "CachingDisabled"
        },
    }
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id: str) -> None:
    """Disable, wait for Deployed, delete; a gone distribution is done, anything else raises."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
        config = cfg["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=cfg["ETag"])
        deadline = time.monotonic() + 900
        while True:
            d = cf.get_distribution(Id=dist_id)
            if d["Distribution"]["Status"] == "Deployed":
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"distribution {dist_id} not Deployed within 900s; not deleted")
            time.sleep(2)
        cf.delete_distribution(Id=dist_id, IfMatch=d["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _mint_dead_tenant_id(ctx, dist_id: str) -> tuple[str, str]:
    """Create a real distribution tenant, capture its Id/ETag, delete it, and hand
    back that now-dead Id -- a correctly-shaped Id guaranteed not to exist."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-optc-tenant-")
    domain = f"{name}.sim2real-cf-optc.com"
    created = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "op-contract-associate-distribution-tenant-web-acl"}]},
    )
    tenant_id = created["DistributionTenant"]["Id"]
    etag = created["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    return tenant_id, etag


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
