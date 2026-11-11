"""distribution-invalid-target-origin-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"


def _minimal_distribution_config(ctx, comment="", enabled=True, origin_domain=None, origin_id="primary-origin"):
    """Build a minimal-but-valid DistributionConfig with a single custom origin."""
    domain = origin_domain or f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {
            "Quantity": 1,
            "Items": [{
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
            }],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }


def _client_error(fn):
    """Call fn(); return the botocore Error dict with HTTPStatusCode. An unexpected success raises,
    so a target that accepts a call AWS refuses fails as an accepted call, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return dict(exc.response.get("Error", {}), HTTPStatusCode=status)
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=15.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _delete_when_deployed(cf, dist_id, timeout_s=850.0):
    """Wait for the distribution to read Deployed, then delete it; a missing one is already gone."""
    try:
        got = _poll_until(
            lambda: cf.get_distribution(Id=dist_id),
            lambda r: r["Distribution"]["Status"] == "Deployed",
            timeout_s=timeout_s,
            description=f"distribution {dist_id} reaching Deployed before delete",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cf.delete_distribution(Id=dist_id, IfMatch=got["ETag"])


#: The positive control's Deployed wait, sized from the CloudFront (long) service-class budget.
_LONG_BUDGET_S = 1700

CHECK = "distribution-invalid-target-origin-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A distribution whose TargetOriginId names its own origin is accepted, deploys and is listed, while
    the same config with a TargetOriginId naming no origin is refused with NoSuchOrigin (HTTP 404) and
    the exact message and creates no distribution."""
    cf = ctx.client("cloudfront")

    good_comment = ctx.unique_name("sim2real-behav-cf-good-")
    good_cfg = _minimal_distribution_config(ctx, comment=good_comment, enabled=False)
    good_resp = cf.create_distribution(DistributionConfig=good_cfg)
    dist = good_resp["Distribution"]
    dist_id = dist["Id"]

    ctx.on_cleanup(lambda: _delete_when_deployed(cf, dist_id))
    assert dist["Status"] in ("InProgress", "Deployed"), (
        f"expected CreateDistribution to report InProgress or Deployed, got {dist['Status']!r}"
    )
    assert dist.get("DomainName"), "expected a DomainName to be assigned at creation"

    # The distribution must fully deploy before it can be deleted; the body waits for Deployed
    # here so the cleanup registered above is normally a single fast delete.
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=_LONG_BUDGET_S,
        description=f"positive-control distribution {dist_id} reaching Deployed",
    )

    listed = cf.list_distributions().get("DistributionList", {}).get("Items", [])
    assert any(d.get("Id") == dist_id for d in listed), (
        "positive-control distribution should be visible in ListDistributions"
    )

    bad_comment = ctx.unique_name("sim2real-behav-cf-bad-")
    bad_cfg = _minimal_distribution_config(ctx, comment=bad_comment, enabled=False)
    bad_cfg["DefaultCacheBehavior"]["TargetOriginId"] = "does-not-exist"

    err = _client_error(lambda: cf.create_distribution(DistributionConfig=bad_cfg))
    assert err.get("Code") == "NoSuchOrigin", f"expected NoSuchOrigin, got {err.get('Code')}"
    # The Smithy model declares NoSuchOrigin with httpError 404.
    assert err.get("HTTPStatusCode") == 404, f"expected HTTP 404 for NoSuchOrigin, got {err.get('HTTPStatusCode')!r}"
    expected_message = "One or more of your cache behavior target origins or origin groups do not exist."
    assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'

    listed_after = cf.list_distributions().get("DistributionList", {}).get("Items", [])
    assert all(d.get("Comment") != bad_comment for d in listed_after), (
        "rejected create must not have produced a distribution"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
