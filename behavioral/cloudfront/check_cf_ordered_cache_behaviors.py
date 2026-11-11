"""cf-ordered-cache-behaviors."""
from __future__ import annotations

import time
import itertools

from behavioral_harness import tags

_COUNTER = itertools.count()

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"

def _minimal_distribution_config(ctx, comment="", enabled=True, origin_domain=None, origin_id="primary-origin", extra_origins=None):
    """Build a minimal-but-valid DistributionConfig with a single custom origin."""
    domain = origin_domain or f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [{
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }]
    if extra_origins:
        origins.extend(extra_origins)
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }

CHECK = "cf-ordered-cache-behaviors"
GROUP = 'cache-behaviors'
SERVICES = ['cloudfront']

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

def _custom_origin(origin_id: str, domain: str) -> dict:
    return {
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistributionConfig returns two overlapping CacheBehaviors (/api/v1/* before /api/*) in
    the submitted order with their distinct target origins, since list order is CloudFront's
    precedence rule; the default behavior keeps the primary origin."""
    cf = ctx.client("cloudfront")
    api_domain = f"{ctx.unique_name('sim2real-behav-api-')}.example.com"
    v1_domain = f"{ctx.unique_name('sim2real-behav-v1-')}.example.com"
    cfg = _minimal_distribution_config(ctx,
        comment="sim2real ordered-behaviors",
        origin_id="primary-origin",
        extra_origins=[
            _custom_origin("api-origin", api_domain),
            _custom_origin("v1-origin", v1_domain),
        ],
    )
    # Deliberately overlapping and NOT alphabetical: /api/v1/* is more specific
    # than /api/* and must be evaluated first, so submission order is what a
    # correct target must preserve verbatim.
    submitted = [
        ("/api/v1/*", "v1-origin"),
        ("/api/*", "api-origin"),
    ]
    cfg["CacheBehaviors"] = {
        "Quantity": len(submitted),
        "Items": [
            {
                "PathPattern": pattern,
                "TargetOriginId": origin,
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
            }
            for pattern, origin in submitted
        ],
    }
    resp = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": cfg,
        "Tags": {"Items": [{"Key": "sim2real-check", "Value": "true"}]},
    })
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    got = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]

    # All three origins present.
    origin_ids = {o["Id"] for o in got["Origins"]["Items"]}
    assert {"primary-origin", "api-origin", "v1-origin"} <= origin_ids, origin_ids

    # Default behavior routes to the primary origin.
    assert got["DefaultCacheBehavior"]["TargetOriginId"] == "primary-origin", (
        got["DefaultCacheBehavior"]["TargetOriginId"]
    )

    # The ordered behaviors survive in the EXACT submitted order. A target that
    # stores behaviors unordered (a dict/set) or re-sorts by pattern would
    # return ("/api/*", "api-origin") first here, since it sorts before
    # "/api/v1/*" alphabetically -- only verbatim order-preservation passes.
    behaviors = got.get("CacheBehaviors", {})
    assert behaviors.get("Quantity") == len(submitted), behaviors
    items = behaviors["Items"]
    got_patterns = [b["PathPattern"] for b in items]
    got_origins = [b["TargetOriginId"] for b in items]
    assert got_patterns == [pattern for pattern, _ in submitted], (
        f"path patterns must be returned in the submitted order, got {got_patterns}"
    )
    assert got_origins == [origin for _, origin in submitted], (
        f"target origins must be returned in the submitted order, got {got_origins}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
