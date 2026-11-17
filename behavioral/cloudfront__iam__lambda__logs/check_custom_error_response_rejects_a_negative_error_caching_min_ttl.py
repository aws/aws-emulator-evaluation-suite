"""custom-error-response-rejects-a-negative-error-caching-min-ttl."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-error-response-rejects-a-negative-error-caching-min-ttl"
GROUP = "caching"
SERVICES = ["cloudfront"]

#: The managed CachingOptimized cache policy: any valid policy id works here, nothing in this
#: check depends on its TTLs.
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

_NEGATIVE_TTL_REJECTED = (
    "InvalidArgument",
    "The parameter ErrorCachingMinTTL is not within allowed range.",
)


def _expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; raise on a mismatch or an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response["Error"]["Code"]
        actual_message = exc.response["Error"].get("Message", "")
        assert actual_code == code, f"expected code {code!r}, got {actual_code!r} ({actual_message!r})"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Wait for the already-disabled distribution to deploy, then delete."""
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _distribution_config(ctx, suffix: str, error_caching_min_ttl: int) -> dict:
    return {
        "CallerReference": ctx.unique_name(f"sim2real-behav-cferrneg-{suffix}-"),
        "Comment": "sim2real negative ErrorCachingMinTTL rejected",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "o1",
            "DomainName": "docs.aws.amazon.com",
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            },
        }]},
        "CustomErrorResponses": {"Quantity": 1, "Items": [
            {"ErrorCode": 502, "ErrorCachingMinTTL": error_caching_min_ttl},
        ]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "o1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution refuses a CustomErrorResponse whose ErrorCachingMinTTL is negative; the
    same config with the valid boundary 0 is created and reads back 0.
    """
    cf = ctx.client("cloudfront")

    _expect_error(
        lambda: cf.create_distribution(DistributionConfig=_distribution_config(ctx, "neg", -1)),
        *_NEGATIVE_TTL_REJECTED,
    )

    dist = cf.create_distribution(
        DistributionConfig=_distribution_config(ctx, "ok", 0))["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))

    stored = dist["DistributionConfig"]["CustomErrorResponses"]["Items"][0]
    assert stored["ErrorCachingMinTTL"] == 0, (
        f"expected the boundary value 0 to be accepted and stored, got {stored!r}"
    )

    read_back = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert read_back["CustomErrorResponses"]["Items"][0]["ErrorCachingMinTTL"] == 0, (
        f"expected a later read to still show the boundary value 0, got "
        f"{read_back['CustomErrorResponses']['Items'][0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
