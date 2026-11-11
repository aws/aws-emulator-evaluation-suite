"""distribution-cache-behavior-order-preserved."""
from __future__ import annotations

import copy
import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_COUNTER = itertools.count()

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    """Run fn and return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out waiting for {description} after {timeout_s}s (last: {last!r})"
    )


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag.

    CloudFront is a globally scoped service and a distribution deployment
    routinely takes several minutes, so the deadline is deliberately long.
    """
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe,
        lambda status: status == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} Status=Deployed",
    )
    return holder["etag"]


def _force_delete_distribution(cf, dist_id):
    """Teardown: disable if needed, wait for Deployed, delete with the current ETag."""
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


def _custom_origin(origin_id, domain):
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


def _minimal_distribution_config(
    ctx, comment="", enabled=False, origin_id="primary-origin", extra_origins=None
):
    """Minimal-but-valid DistributionConfig with a single custom origin.

    Enabled defaults to False: a disabled distribution still has to reach
    Deployed before DeleteDistribution is accepted, but teardown then skips the
    extra disable-and-redeploy round trip.
    """
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [_custom_origin(origin_id, domain)]
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
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    }


def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


CHECK = "distribution-cache-behavior-order-preserved"
GROUP = 'cache-behaviors'
SERVICES = ['cloudfront']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CacheBehaviors keep the submitted order (the precedence rule) on Create, Get and List,
    and UpdateDistribution persists a reorder; a partial behaviour struct on update is rejected.

    Reference: https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateDistribution.html
    """
    cf = ctx.client("cloudfront")
    api_domain = f"{ctx.unique_name('sim2real-behav-api-')}.example.com"
    img_domain = f"{ctx.unique_name('sim2real-behav-img-')}.example.com"
    cfg = _minimal_distribution_config(
        ctx,
        comment="sim2real behavior-order",
        extra_origins=[
            _custom_origin("api-origin", api_domain),
            _custom_origin("img-origin", img_domain),
        ],
    )

    def _behavior(pattern, origin):
        return {
            "PathPattern": pattern,
            "TargetOriginId": origin,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        }

    # Deliberately NOT alphabetical, and deliberately overlapping: /api/v1/* is
    # more specific than /api/* and must be evaluated first.
    submitted = [
        ("/api/v1/*", "api-origin"),
        ("/api/*", "primary-origin"),
        ("/images/*.jpg", "img-origin"),
    ]
    cfg["CacheBehaviors"] = {
        "Quantity": len(submitted),
        "Items": [_behavior(p, o) for p, o in submitted],
    }
    created = cf.create_distribution(DistributionConfig=cfg)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    def _pairs(behaviors):
        return [(b["PathPattern"], b["TargetOriginId"]) for b in behaviors.get("Items", []) or []]

    assert _pairs(created["Distribution"]["DistributionConfig"]["CacheBehaviors"]) == submitted, (
        "CreateDistribution must echo the cache behaviours in the submitted order, got "
        f"{_pairs(created['Distribution']['DistributionConfig']['CacheBehaviors'])}"
    )

    stored = cf.get_distribution_config(Id=dist_id)
    etag = stored["ETag"]
    behaviors = stored["DistributionConfig"]["CacheBehaviors"]
    assert behaviors["Quantity"] == 3, behaviors["Quantity"]
    assert _pairs(behaviors) == submitted, (
        f"cache behaviour order must be preserved verbatim, got {_pairs(behaviors)}"
    )
    # The default behaviour is NOT one of the ordered behaviours.
    assert "*" not in [p for p, _ in _pairs(behaviors)], (
        "DefaultCacheBehavior must not be materialised as a '*' entry in CacheBehaviors: "
        f"{_pairs(behaviors)}"
    )
    assert stored["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"] == (
        "primary-origin"
    ), stored["DistributionConfig"]["DefaultCacheBehavior"]["TargetOriginId"]

    summary = None
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []) or []:
            if item["Id"] == dist_id:
                summary = item
    assert summary is not None, f"{dist_id} must appear in ListDistributions"
    assert _pairs(summary["CacheBehaviors"]) == submitted, (
        "the ListDistributions summary must project the same behaviour order, got "
        f"{_pairs(summary['CacheBehaviors'])}"
    )

    # The struct CreateDistribution accepted is rejected by UpdateDistribution: create defaults
    # the optional flags (e.g. SmoothStreaming) in, update requires them.
    reordered = list(reversed(submitted))
    partial_cfg = copy.deepcopy(stored["DistributionConfig"])
    partial_cfg["CacheBehaviors"] = {
        "Quantity": len(reordered),
        "Items": [_behavior(p, o) for p, o in reordered],
    }
    partial_code, partial_msg = _error(
        lambda: cf.update_distribution(
            Id=dist_id, IfMatch=etag, DistributionConfig=partial_cfg
        )
    )
    assert partial_code == "InvalidArgument", (
        "UpdateDistribution must reject a cache behaviour that omits the flags "
        "CreateDistribution defaults in, with InvalidArgument; got "
        f"{partial_code!r}: {partial_msg!r}"
    )
    assert partial_msg == "The parameter SmoothStreaming flag is missing.", (
        "InvalidArgument is CloudFront's catch-all, so the message is what attributes the "
        f"refusal to the missing behaviour flag; got {partial_msg!r}"
    )

    unchanged = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["CacheBehaviors"]
    assert _pairs(unchanged) == submitted, (
        f"a rejected UpdateDistribution must not reorder anything, got {_pairs(unchanged)}"
    )

    # UpdateDistribution is a whole-config replace: permute the behaviours AWS returned (flags
    # and all) and send the config back under its ETag, so only the order differs.
    by_pattern = {b["PathPattern"]: b for b in behaviors["Items"]}
    assert sorted(by_pattern) == sorted(p for p, _ in submitted), by_pattern.keys()
    full_cfg = copy.deepcopy(stored["DistributionConfig"])
    full_cfg["CacheBehaviors"] = {
        "Quantity": len(reordered),
        "Items": [copy.deepcopy(by_pattern[p]) for p, _ in reordered],
    }
    cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=full_cfg)
    after = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["CacheBehaviors"]
    assert _pairs(after) == reordered, (
        f"UpdateDistribution must persist the reordered behaviours, got {_pairs(after)}"
    )
    assert after["Quantity"] == len(reordered), after["Quantity"]
    assert {b["PathPattern"] for b in after["Items"]} == set(by_pattern), (
        f"reordering must not add or drop behaviours, got {_pairs(after)}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
