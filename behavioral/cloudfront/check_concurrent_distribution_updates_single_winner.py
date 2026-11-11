"""concurrent-distribution-updates-single-winner."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

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

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order (exceptions captured, not raised)."""
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()
    def cap(fut, i):
        try:
            results[i] = fut.result()
        except Exception as e:  # noqa: BLE001 — captured for the caller to assert on
            results[i] = e
        resolved.add(i)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        f2i = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(f2i, timeout=timeout_s):
                cap(fut, f2i[fut])
        except concurrent.futures.TimeoutError as te:
            for fut, i in f2i.items():
                if i in resolved:
                    continue
                if fut.done():
                    cap(fut, i)
                else:
                    fut.cancel()
                    results[i] = te
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

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

def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    # Tagged at creation (CreateDistributionWithTags, not CreateDistribution) so a tag search
    # can find this distribution if cleanup is ever abandoned mid-poll.
    resp = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": cfg,
        "Tags": {"Items": [{"Key": "sim2real-check", "Value": "true"}]},
    })
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp

CHECK = "concurrent-distribution-updates-single-winner"
GROUP = 'concurrency'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent UpdateDistribution calls sharing one stale-capable ETag: exactly one wins."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="race-start")
    dist_id = resp["Distribution"]["Id"]
    _wait_distribution_deployed(cf, dist_id)

    cfg_resp = cf.get_distribution_config(Id=dist_id)
    shared_etag = cfg_resp["ETag"]
    base_cfg = cfg_resp["DistributionConfig"]

    comments = [f"race-{i}" for i in range(5)]

    def make_updater(comment: str):
        def _do():
            cfg = dict(base_cfg)
            cfg["Comment"] = comment
            return cf.update_distribution(Id=dist_id, IfMatch=shared_etag, DistributionConfig=cfg)
        return _do

    racers = [make_updater(c) for c in comments]
    results = _run_concurrent(racers)

    # concurrent_successes returns a COUNT, not a list.
    n_success = _concurrent_successes(results)
    assert n_success == 1, f"expected exactly one winner racing on the same ETag, got {n_success}"

    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == 4, f"expected 4 losers, got {len(error_codes)}"
    assert all(c == "PreconditionFailed" for c in error_codes), (
        f"expected all losers to fail with PreconditionFailed, got {error_codes}")
    error_messages = {r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)}
    assert error_messages == {
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    }, f"PreconditionFailed messages of the losers: {error_messages}"

    winner_comment = next(
        r["Distribution"]["DistributionConfig"]["Comment"]
        for r in results if not isinstance(r, BaseException)
    )
    assert winner_comment in comments, (
        f"the winning racer's own response reports a comment we never sent: {winner_comment!r}")

    # Independent terminal read through GetDistributionConfig — a different operation than the
    # UpdateDistribution calls above — proving the winner's write actually persisted rather than
    # merely being the one that got a 200.
    persisted_comment = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["Comment"]
    assert persisted_comment == winner_comment, (
        f"persisted comment {persisted_comment!r} disagrees with the racer told it won "
        f"({winner_comment!r}) — an independent read must confirm the winner's write stuck")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
