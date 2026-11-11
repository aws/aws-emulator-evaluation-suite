"""create-invalidation-for-tenant-batch-too-large-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-invalidation-for-tenant-batch-too-large-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvalidationForDistributionTenant with an oversized batch fails with code "413"
    (BatchTooLarge) and creates no invalidation; a small batch right after creates one."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_id, _etag = _create_disabled_tenant(ctx, dist_id)

    before = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    before_count = before["InvalidationList"]["Quantity"]
    assert before_count == 0, f"expected a fresh tenant to have 0 invalidations, got {before_count}"

    # An oversized request body -- 60,000 distinct, moderately long paths -- reliably exceeds
    # CloudFront's invalidation batch size limit regardless of the exact per-tenant path count
    # quota (BatchTooLarge is documented as an HTTP 413 payload-too-large response).
    huge_paths = [f"/sim2real-batch-too-large/{i:08d}/{'a' * 40}" for i in range(60000)]
    code = _error_code(
        lambda: cf.create_invalidation_for_distribution_tenant(
            Id=tenant_id,
            InvalidationBatch={
                "CallerReference": ctx.unique_name("sim2real-huge-"),
                "Paths": {"Quantity": len(huge_paths), "Items": huge_paths},
            },
        )
    )
    # botocore reports this condition's code as the HTTP status "413", not the shape name
    # "BatchTooLarge".
    assert code == "413", f"expected 413 (BatchTooLarge), got {code!r}"

    # Effect absent: the oversized batch didn't create an invalidation.
    after = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    after_count = after["InvalidationList"]["Quantity"]
    assert after_count == before_count, (
        f"expected no invalidation to be recorded after the 413 rejection, "
        f"before={before_count} after={after_count}"
    )

    # Positive control: a small batch submitted right after still succeeds.
    ok = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_id,
        InvalidationBatch={
            "CallerReference": ctx.unique_name("sim2real-small-"),
            "Paths": {"Quantity": 1, "Items": ["/small-batch-object.txt"]},
        },
    )
    assert ok["Invalidation"]["Id"], "expected CreateInvalidationForDistributionTenant to return an Id"
    final = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    final_count = final["InvalidationList"]["Quantity"]
    assert final_count == before_count + 1, (
        f"expected exactly one new invalidation after the positive control, "
        f"before={before_count} final={final_count}"
    )


def _error_code(fn):
    """Call fn(); return its error code. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real create-invalidation-for-tenant-batch-too-large-rejected",
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
    # RFC 2606 reserved names (example.com, *.test) are rejected outright by CloudFront's
    # domain validation, so use an ordinary-looking, unregistered .com label instead.
    domain = f"{ctx.unique_name('sim2real-cf-tenant-')}.com"
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        # Every distribution tenant needs at least one certificate. ValidationTokenHost
        # "cloudfront" makes CloudFront verify we control `domain` via DNS before it will
        # even create the tenant; "self-hosted" defers that verification instead of
        # requiring it synchronously here, which is all this check needs -- it only wants a
        # tenant to exist, not a working custom domain.
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
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


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    import time

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
