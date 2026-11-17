"""distribution-many-cache-behaviors-order-and-count-preserved."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_CACHE_BEHAVIOR_COUNT = 26

CHECK = "distribution-many-cache-behaviors-order-and-count-preserved"
GROUP = "cache-behaviors"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistribution with 26 distinct ordered cache behaviors on one origin succeeds;
    GetDistributionConfig reports CacheBehaviors.Quantity 26 in submitted order, and deleting
    the distribution afterwards succeeds.

    Reference: https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateDistribution.html
    """
    cf = ctx.client("cloudfront")

    dist_id, patterns, origin_id = _create_distribution(ctx, cf)
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))

    created = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    created_behaviors = created["CacheBehaviors"]
    assert created_behaviors["Quantity"] == _CACHE_BEHAVIOR_COUNT, (
        f"expected CacheBehaviors.Quantity={_CACHE_BEHAVIOR_COUNT}, got {created_behaviors['Quantity']!r}"
    )
    created_patterns = [b["PathPattern"] for b in created_behaviors["Items"]]
    assert created_patterns == patterns, (
        f"expected the submitted order {patterns!r}, got {created_patterns!r}"
    )

    stored = cf.get_distribution_config(Id=dist_id)
    stored_behaviors = stored["DistributionConfig"]["CacheBehaviors"]
    assert stored_behaviors["Quantity"] == _CACHE_BEHAVIOR_COUNT, (
        f"expected GetDistributionConfig CacheBehaviors.Quantity={_CACHE_BEHAVIOR_COUNT}, "
        f"got {stored_behaviors['Quantity']!r}"
    )
    stored_patterns = [b["PathPattern"] for b in stored_behaviors["Items"]]
    assert stored_patterns == patterns, (
        f"expected GetDistributionConfig to preserve the submitted order, got {stored_patterns!r}"
    )
    stored_targets = {b["TargetOriginId"] for b in stored_behaviors["Items"]}
    assert stored_targets == {origin_id}, (
        f"expected every cache behavior to target {origin_id!r}, got {stored_targets!r}"
    )

    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

    code, message = _error(lambda: cf.get_distribution_config(Id=dist_id))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution after delete, got {code!r}"
    assert message == "The specified distribution does not exist.", (
        f"unexpected NoSuchDistribution message: {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_distribution(ctx, cf):
    origin_id = "primary-origin"
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    patterns = [f"/path-{i:02d}/*" for i in range(_CACHE_BEHAVIOR_COUNT)]
    cfg = {
        "CallerReference": ctx.unique_name("sim2real-behav-cf-") + f"-{next(_COUNTER)}",
        "Comment": "sim2real behavioral check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
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
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "CacheBehaviors": {
            "Quantity": len(patterns),
            "Items": [
                {
                    "PathPattern": pattern,
                    "TargetOriginId": origin_id,
                    "ViewerProtocolPolicy": "redirect-to-https",
                    "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                }
                for pattern in patterns
            ],
        },
    }
    resp = cf.create_distribution(DistributionConfig=cfg)
    return resp["Distribution"]["Id"], patterns, origin_id


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_distribution(cf, dist_id):
    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        etag = updated["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
