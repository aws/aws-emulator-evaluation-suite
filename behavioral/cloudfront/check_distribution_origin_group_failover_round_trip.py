"""distribution-origin-group-failover-round-trip."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


# ===== helpers =====
_COUNTER = itertools.count()

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error_code(fn):
    """Run fn and return the ClientError error code, or None when it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


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

CHECK = "distribution-origin-group-failover-round-trip"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An origin group round-trips with its member order and failover status codes, the default
    behaviour may target the group id, and repointing the behaviour at a real origin removes it.
    """
    cf = ctx.client("cloudfront")
    secondary_domain = f"{ctx.unique_name('sim2real-behav-secondary-')}.example.com"
    cfg = _minimal_distribution_config(
        ctx,
        comment="sim2real origin-group",
        extra_origins=[_custom_origin("secondary-origin", secondary_domain)],
    )
    failover_codes = [403, 404, 502, 503]
    cfg["OriginGroups"] = {
        "Quantity": 1,
        "Items": [
            {
                "Id": "failover-group",
                "FailoverCriteria": {
                    "StatusCodes": {
                        "Quantity": len(failover_codes),
                        "Items": failover_codes,
                    }
                },
                "Members": {
                    "Quantity": 2,
                    "Items": [
                        {"OriginId": "primary-origin"},
                        {"OriginId": "secondary-origin"},
                    ],
                },
            }
        ],
    }
    # The default behaviour targets the GROUP, not an origin.
    cfg["DefaultCacheBehavior"]["TargetOriginId"] = "failover-group"

    created = cf.create_distribution(DistributionConfig=cfg)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    stored = cf.get_distribution_config(Id=dist_id)
    etag = stored["ETag"]
    got = stored["DistributionConfig"]
    groups = got.get("OriginGroups") or {}
    assert groups.get("Quantity") == 1, f"expected exactly one origin group, got {groups}"
    group = groups["Items"][0]
    assert group["Id"] == "failover-group", group["Id"]

    members = [m["OriginId"] for m in group["Members"]["Items"]]
    assert members == ["primary-origin", "secondary-origin"], (
        "origin-group member order encodes failover precedence and must be preserved verbatim, "
        f"got {members}"
    )
    assert group["Members"]["Quantity"] == 2, group["Members"]["Quantity"]

    codes = group["FailoverCriteria"]["StatusCodes"]
    assert codes["Quantity"] == len(failover_codes), codes
    assert sorted(codes["Items"]) == sorted(failover_codes), (
        f"failover status codes must round-trip, got {codes['Items']}"
    )

    assert got["DefaultCacheBehavior"]["TargetOriginId"] == "failover-group", (
        "a cache behaviour must be allowed to target an origin group id, got "
        f"{got['DefaultCacheBehavior']['TargetOriginId']}"
    )
    # Both member origins are still declared under Origins.
    origin_ids = {o["Id"] for o in got["Origins"]["Items"]}
    assert {"primary-origin", "secondary-origin"} <= origin_ids, origin_ids

    # GetDistribution's nested copy agrees with GetDistributionConfig.
    nested = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert nested.get("OriginGroups") == groups, (
        "GetDistribution must report the same OriginGroups document as GetDistributionConfig"
    )

    # Remove the group: repoint the default behaviour at a real origin first,
    # otherwise the behaviour would reference a group that no longer exists.
    got["DefaultCacheBehavior"]["TargetOriginId"] = "primary-origin"
    got["OriginGroups"] = {"Quantity": 0, "Items": []}
    cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=got)
    after = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert (after.get("OriginGroups") or {}).get("Quantity") == 0, (
        f"the origin group must be gone after the update, got {after.get('OriginGroups')}"
    )
    assert after["DefaultCacheBehavior"]["TargetOriginId"] == "primary-origin", (
        after["DefaultCacheBehavior"]["TargetOriginId"]
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
