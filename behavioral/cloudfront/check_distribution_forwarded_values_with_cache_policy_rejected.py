"""distribution-forwarded-values-with-cache-policy-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
_COUNTER = itertools.count()

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_MIN_TTL_WITH_CACHE_POLICY = (
    "The parameter MinTTL cannot be used when a cache policy is associated to the cache behavior."
)


def _error(fn):
    """Run fn and return the ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


# ===== end helpers =====

CHECK = "distribution-forwarded-values-with-cache-policy-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache behavior using both a cache policy and legacy ForwardedValues is rejected with
    InvalidArgument, while the modern-only and legacy-only configs are each accepted.
    """
    cf = ctx.client("cloudfront")

    legacy_forwarded_values = {
        "QueryString": False,
        "Cookies": {"Forward": "none"},
        "Headers": {"Quantity": 0},
        "QueryStringCacheKeys": {"Quantity": 0},
    }

    # 1. Negative: both generations in the same DefaultCacheBehavior.
    conflicting = _minimal_distribution_config(ctx, comment="sim2real fv-conflict")
    conflicting["DefaultCacheBehavior"].update(
        {
            "ForwardedValues": legacy_forwarded_values,
            "MinTTL": 0,
            "DefaultTTL": 86400,
            "MaxTTL": 31536000,
        }
    )
    code, message = _error(lambda: cf.create_distribution(DistributionConfig=conflicting))
    assert code == "InvalidArgument", (
        "CachePolicyId together with legacy ForwardedValues must be rejected with "
        f"InvalidArgument, got {code}"
    )
    assert message == _MIN_TTL_WITH_CACHE_POLICY, f"expected message {_MIN_TTL_WITH_CACHE_POLICY!r}, got {message!r}"

    # Effect absent: the rejected create must not have minted a distribution.
    # CallerReference is not exposed by ListDistributions, so match on the Comment marker.
    leaked = []
    for page in cf.get_paginator("list_distributions").paginate():
        for summary in page["DistributionList"].get("Items", []) or []:
            if summary.get("Comment") == "sim2real fv-conflict":
                leaked.append(summary["Id"])
    assert not leaked, (
        f"a rejected CreateDistribution must not leave a distribution behind, found {leaked}"
    )

    # 2. Control A: modern only (CachePolicyId, no ForwardedValues) is accepted.
    modern = _create_distribution(cf, ctx, comment="sim2real fv-conflict modern-ok")
    modern_cfg = cf.get_distribution_config(Id=modern["Distribution"]["Id"])["DistributionConfig"]
    assert modern_cfg["DefaultCacheBehavior"]["CachePolicyId"] == MANAGED_CACHING_OPTIMIZED, (
        modern_cfg["DefaultCacheBehavior"].get("CachePolicyId")
    )
    assert "ForwardedValues" not in modern_cfg["DefaultCacheBehavior"], (
        "a policy-based behavior must not be back-filled with legacy ForwardedValues: "
        f"{modern_cfg['DefaultCacheBehavior'].get('ForwardedValues')}"
    )

    # 3. Control B: legacy only (ForwardedValues + TTL triple, no CachePolicyId)
    #    is STILL accepted, and round-trips verbatim.
    legacy = _minimal_distribution_config(ctx, comment="sim2real fv-conflict legacy-ok")
    legacy["DefaultCacheBehavior"] = {
        "TargetOriginId": "primary-origin",
        "ViewerProtocolPolicy": "redirect-to-https",
        "ForwardedValues": legacy_forwarded_values,
        "MinTTL": 5,
        "DefaultTTL": 300,
        "MaxTTL": 600,
    }
    legacy_resp = cf.create_distribution(DistributionConfig=legacy)
    legacy_id = legacy_resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, legacy_id))
    legacy_cfg = cf.get_distribution_config(Id=legacy_id)["DistributionConfig"]
    behavior = legacy_cfg["DefaultCacheBehavior"]
    assert behavior["ForwardedValues"]["Cookies"]["Forward"] == "none", behavior["ForwardedValues"]
    assert behavior["MinTTL"] == 5, behavior["MinTTL"]
    assert behavior["DefaultTTL"] == 300, behavior["DefaultTTL"]
    assert behavior["MaxTTL"] == 600, behavior["MaxTTL"]
    assert "CachePolicyId" not in behavior, (
        "a legacy behavior must not be silently migrated onto a managed cache policy: "
        f"{behavior.get('CachePolicyId')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
