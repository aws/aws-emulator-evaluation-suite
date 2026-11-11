"""copy-distribution-lifecycle."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()


def _error_response(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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

def _wait_distribution_status(cf, dist_id, status, *, timeout_s=240, interval_s=5):
    return _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == status,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} reaching status {status}",
    )

def _disable_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    etag = cfg_resp["ETag"]
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        return cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    return etag

def _force_delete_distribution(cf, dist_id):
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution:
        return
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

_SIM2REAL_TAGS = {"Items": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]}

def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    cf.tag_resource(Resource=resp["Distribution"]["ARN"], Tags=_SIM2REAL_TAGS)
    return resp

CHECK = "copy-distribution-lifecycle"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']

# Leaves ~60s margin for the API calls and assertions around the three Deployed waits below,
# consistent with this directory's other CloudFront Deployed-wait ceilings (900s-1200s).
_TOTAL_BUDGET_S = 840.0
_PRIMARY_WAIT_S = 400.0
_MIN_REMAINING_S = 60.0

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyDistribution produces a brand-new, independent Distribution: it
    gets its own Id/ARN, reaches Deployed on its own, and follows the exact
    same Get/Delete lifecycle as a directly-created distribution."""
    cf = ctx.client("cloudfront")
    started = time.monotonic()
    primary_resp = _create_distribution(cf, ctx, comment="cpysrc")
    primary_id = primary_resp["Distribution"]["Id"]
    primary_arn = primary_resp["Distribution"]["ARN"]
    try:
        _wait_distribution_status(cf, primary_id, "Deployed", timeout_s=_PRIMARY_WAIT_S, interval_s=5)
    except AssertionError as exc:
        raise AssertionError(
            f"primary distribution did not reach Deployed within the "
            f"per-check budget: {exc}",
        ) from exc

    primary_etag = cf.get_distribution_config(Id=primary_id)["ETag"]
    copy_ref = ctx.unique_name("sim2real-behav-cpy-")
    copy_resp = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        Staging=True,
        IfMatch=primary_etag,
        CallerReference=copy_ref,
        Enabled=True,
    )
    copy_dist = copy_resp["Distribution"]
    copy_id = copy_dist["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, copy_id))
    cf.tag_resource(Resource=copy_dist["ARN"], Tags=_SIM2REAL_TAGS)
    assert copy_id != primary_id, f"copy must have its own Id, got the same as primary: {copy_id}"
    assert copy_dist["ARN"] != primary_arn, (
        f"copy must have its own ARN, got the same as primary: {copy_dist['ARN']}"
    )

    remaining = _TOTAL_BUDGET_S - (time.monotonic() - started)
    if remaining < _MIN_REMAINING_S:
        raise AssertionError(
            "primary Deployed propagation used nearly the entire per-check "
            "wall-clock budget; the copy's Deployed/delete/404 tail cannot "
            "run within budget"
        )
    try:
        _wait_distribution_status(cf, copy_id, "Deployed", timeout_s=remaining, interval_s=5)
    except AssertionError as exc:
        raise AssertionError(
            f"copy distribution did not reach Deployed within the remaining "
            f"per-check budget ({remaining:.0f}s): {exc}",
        ) from exc

    get_resp = cf.get_distribution(Id=copy_id)
    assert get_resp["Distribution"]["Id"] == copy_id, (
        f"expected an independent read of {copy_id}, got {get_resp['Distribution']['Id']}"
    )

    remaining2 = _TOTAL_BUDGET_S - (time.monotonic() - started)
    if remaining2 < _MIN_REMAINING_S:
        raise AssertionError(
            "insufficient remaining per-check budget to disable+delete the "
            "copy distribution and assert the post-delete 404"
        )
    try:
        _disable_distribution(cf, copy_id)
        _wait_distribution_status(cf, copy_id, "Deployed", timeout_s=remaining2, interval_s=5)
    except AssertionError as exc:
        raise AssertionError(
            f"copy distribution did not return to Deployed after disabling "
            f"within the remaining per-check budget: {exc}"
        ) from exc
    final_etag = cf.get_distribution_config(Id=copy_id)["ETag"]
    cf.delete_distribution(Id=copy_id, IfMatch=final_etag)

    err = _error_response(lambda: cf.get_distribution(Id=copy_id))
    got = (err.get("Code"), err.get("Message"))
    expected = ("NoSuchDistribution", "The specified distribution does not exist.")
    assert got == expected, f"expected {expected} after delete, got {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
