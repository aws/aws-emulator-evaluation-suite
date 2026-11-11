"""invalidation-list-ordering-most-recent-first."""
from __future__ import annotations

import time
import itertools

from behavioral_harness import tags

_COUNTER = itertools.count()

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out waiting for {description} after {timeout_s:.0f}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=2, etag_hint=None, ctx=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag. With ctx the wait
    is capped by the run budget; teardown passes none."""
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} reaching Deployed", ctx=ctx)
    return holder["etag"]

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, interval_s=15, etag_hint=etag)
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

def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp

CHECK = "invalidation-list-ordering-most-recent-first"
GROUP = 'invalidation'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvalidations returns created invalidations, most recently created first."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="invalidation-listing")
    dist_id = resp["Distribution"]["Id"]
    _wait_distribution_deployed(cf, dist_id, ctx=ctx)

    created_ids = []
    for i, path in enumerate(["/a.txt", "/b.txt", "/c.txt"]):
        inv = cf.create_invalidation(
            DistributionId=dist_id,
            InvalidationBatch={"Paths": {"Quantity": 1, "Items": [path]},
                                "CallerReference": _caller_reference(ctx, f"inv-list-{i}")},
        )["Invalidation"]
        created_ids.append(inv["Id"])
        # A distinguishable gap between creates, so ordering is never decided by a tie.
        time.sleep(1.5)

    items = cf.list_invalidations(DistributionId=dist_id)["InvalidationList"]["Items"]
    listed_ids = [i["Id"] for i in items]
    assert set(created_ids) <= set(listed_ids), (
        f"expected all of {created_ids} listed, got {listed_ids}"
    )
    # ListInvalidationsRequest.Marker documents decreasing order from most recent to oldest; it
    # orders nothing among batches listed with the same CreateTime.
    listed_at = {i["Id"]: i["CreateTime"] for i in items}
    observed = [i for i in listed_ids if i in created_ids]
    times = [listed_at[i] for i in observed]
    assert times == sorted(times, reverse=True), (
        f"ListInvalidations should return most-recently-created first: got {observed} created at "
        f"{times}"
    )
    # Every pair listed with distinct CreateTimes keeps creation order, newest first.
    position = {inv: k for k, inv in enumerate(observed)}
    for older, newer in itertools.combinations(created_ids, 2):
        if listed_at[older] != listed_at[newer]:
            assert listed_at[newer] > listed_at[older] and position[newer] < position[older], (
                f"ListInvalidations should return most-recently-created first: {newer} was "
                f"created after {older} but is listed at {listed_at[newer]} vs {listed_at[older]}, "
                f"in order {observed}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
