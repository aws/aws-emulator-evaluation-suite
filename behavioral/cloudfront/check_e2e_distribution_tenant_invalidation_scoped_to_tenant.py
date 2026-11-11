"""e2e-distribution-tenant-invalidation-scoped-to-tenant."""
from __future__ import annotations

import time

from behavioral_harness import tags

_WRONG_TENANT_INVALIDATION = "The specified invalidation does not exist."


CHECK = "e2e-distribution-tenant-invalidation-scoped-to-tenant"
GROUP = "e2e"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An invalidation created for one distribution tenant completes and is listed and readable under that
    tenant only: a sibling tenant of the same distribution lists none and reading it through the
    sibling returns EntityNotFound with the exact message."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_a, _etag_a = _create_disabled_tenant(ctx, dist_id)
    tenant_b, _etag_b = _create_disabled_tenant(ctx, dist_id)

    before_a = cf.list_invalidations_for_distribution_tenant(Id=tenant_a)
    before_b = cf.list_invalidations_for_distribution_tenant(Id=tenant_b)
    assert before_a["InvalidationList"]["Quantity"] == 0
    assert before_b["InvalidationList"]["Quantity"] == 0

    created = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_a,
        InvalidationBatch={
            "CallerReference": ctx.unique_name("sim2real-tenant-a-"),
            "Paths": {"Quantity": 1, "Items": ["/tenant-a-only.txt"]},
        },
    )
    inval_id = created["Invalidation"]["Id"]
    _wait_invalidation_completed(ctx, tenant_a, inval_id)

    # Resulting state on the OWNING tenant: the invalidation is tracked there.
    after_a = cf.list_invalidations_for_distribution_tenant(Id=tenant_a)
    assert after_a["InvalidationList"]["Quantity"] == 1
    a_items = after_a["InvalidationList"].get("Items", [])
    assert any(item["Id"] == inval_id for item in a_items), (
        f"invalidation {inval_id} not listed under its own tenant: {a_items!r}"
    )
    fetched_via_a = cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_a, Id=inval_id)
    assert fetched_via_a["Invalidation"]["InvalidationBatch"]["Paths"]["Items"] == ["/tenant-a-only.txt"]

    # Resulting state on the SIBLING tenant: untouched, both in its list and by direct lookup.
    after_b = cf.list_invalidations_for_distribution_tenant(Id=tenant_b)
    assert after_b["InvalidationList"]["Quantity"] == 0, (
        "sibling tenant's invalidation list changed after invalidating a different tenant"
    )
    code, message = _error(
        lambda: cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_b, Id=inval_id)
    )
    # A real invalidation Id fetched under the wrong tenant is EntityNotFound, distinct from the
    # NoSuchInvalidation a never-issued Id gets under the correct tenant.
    assert code == "EntityNotFound", (
        f"expected EntityNotFound fetching tenant A's invalidation via tenant B, got {code!r}"
    )
    assert message == _WRONG_TENANT_INVALIDATION, f"expected message {_WRONG_TENANT_INVALIDATION!r}, got {message!r}"


def _error(fn):
    """Run fn and return the ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real e2e-distribution-tenant-invalidation-scoped-to-tenant",
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id


def _create_disabled_tenant(ctx, dist_id: str):
    cf = ctx.client("cloudfront")
    # NOTE: CloudFront denylists *.example.com/.example.org/.example.net outright with
    # InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved
    # documentation domains. A random, unregistered .com name passes the same
    # format/denylist check without requiring us to own or DNS-validate it (ownership is
    # validated later, via the pending managed-certificate TXT record).
    raw = ctx.unique_name("sim2real-cf-tenant-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    domain = f"{cleaned}.com"
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        # Every tenant needs a certificate; "self-hosted" leaves it pending for a domain whose DNS
        # the caller does not control, while "cloudfront" refuses such a domain at create time
        # (InvalidArgument "Could not verify Domain Name ownership").
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
        },
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id, resp["ETag"]


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_invalidation_completed(ctx, tenant_id: str, inval_id: str, timeout_s: float = 600.0, interval_s: float = 10.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_invalidation_for_distribution_tenant(DistributionTenantId=tenant_id, Id=inval_id)
        if resp["Invalidation"]["Status"] == "Completed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {inval_id} never reached Completed within {timeout_s}s")


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
