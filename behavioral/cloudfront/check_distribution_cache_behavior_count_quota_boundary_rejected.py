"""distribution-cache-behavior-count-quota-boundary-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_CACHE_BEHAVIOR_LIMIT = 74
_TOO_MANY_CACHE_BEHAVIORS = (
    "TooManyCacheBehaviors",
    "Your request contains more CacheBehaviors than are allowed per distribution.",
)

CHECK = "distribution-cache-behavior-count-quota-boundary-rejected"
GROUP = "quotas"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution with one more ordered cache behavior than the per-distribution limit
    is rejected with TooManyCacheBehaviors, while a distribution at the limit is created, reports
    every cache behavior and deletes.
    """
    cf = ctx.client("cloudfront")

    over_cfg, _ = _distribution_config(ctx, _CACHE_BEHAVIOR_LIMIT + 1)
    expect_error(
        lambda: cf.create_distribution(DistributionConfig=over_cfg), *_TOO_MANY_CACHE_BEHAVIORS
    )

    at_cfg, patterns = _distribution_config(ctx, _CACHE_BEHAVIOR_LIMIT)
    resp = cf.create_distribution(DistributionConfig=at_cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(_teardown(lambda: _delete_distribution(cf, dist_id), "NoSuchDistribution"))

    stored = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    stored_behaviors = stored["CacheBehaviors"]
    assert stored_behaviors["Quantity"] == _CACHE_BEHAVIOR_LIMIT, (
        f"expected CacheBehaviors.Quantity={_CACHE_BEHAVIOR_LIMIT}, got {stored_behaviors['Quantity']!r}"
    )
    stored_patterns = [b["PathPattern"] for b in stored_behaviors["Items"]]
    assert stored_patterns == patterns, (
        f"expected the submitted order {patterns!r}, got {stored_patterns!r}"
    )

    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

    code, message = _error(lambda: cf.get_distribution_config(Id=dist_id))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution after delete, got {code!r}"
    assert message == "The specified distribution does not exist.", (
        f"unexpected NoSuchDistribution message: {message!r}"
    )


def expect_error(fn, expected_code: str, expected_message: str) -> None:
    code, message = _error(fn)
    assert code == expected_code, f"expected error code {expected_code!r}, got {code!r}"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _distribution_config(ctx, behavior_count: int):
    origin_id = "primary-origin"
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    patterns = [f"/path-{i:04d}/*" for i in range(behavior_count)]
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
    return cfg, patterns


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _delete_distribution(cf, dist_id):
    current = cf.get_distribution_config(Id=dist_id)
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
