"""distribution-delete-without-disabling-rejected."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

def _error(fn):
    """Call fn(); return its botocore (code, message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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

def _force_delete_distribution(cf, dist_id):
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise

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

CHECK = "distribution-delete-without-disabling-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An emulator must refuse to delete an enabled distribution with DistributionNotDisabled,
    leave it in place, and then accept the identical delete once the same distribution is
    disabled and that disable has fully deployed."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="must-stay-enabled")
    dist_id = resp["Distribution"]["Id"]
    etag = _wait_distribution_deployed(cf, dist_id)

    # break: delete while enabled is rejected
    code, message, status = _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=etag))
    assert code == "DistributionNotDisabled", f"expected DistributionNotDisabled, got {code}"
    assert status == 409, f"expected HTTP 409 for DistributionNotDisabled, got {status!r}"
    assert message == "The distribution you are trying to delete has not been disabled.", (
        f"DeleteDistribution DistributionNotDisabled message: {message!r}"
    )

    # effect absent: an independent read shows it is still there and still enabled
    still_there = cf.get_distribution(Id=dist_id)["Distribution"]
    assert still_there["DistributionConfig"]["Enabled"] is True, (
        f"rejected delete must not disable the distribution as a side effect, "
        f"got Enabled={still_there['DistributionConfig']['Enabled']!r}"
    )

    # restore: disable it and let the disable fully deploy
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    cfg["Enabled"] = False
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    final_etag = _wait_distribution_deployed(cf, dist_id)

    # the identical delete now succeeds
    cf.delete_distribution(Id=dist_id, IfMatch=final_etag)

    # gone and unusable: an independent read reports the specific not-found code, and a
    # mutation on the dead id also fails with it
    def _assert_no_such(result, what):
        got_code, got_message, got_status = result
        assert got_code == "NoSuchDistribution", f"{what}: expected NoSuchDistribution, got {got_code}"
        assert got_status == 404, f"{what}: expected HTTP 404, got {got_status!r}"
        assert (got_message or "").strip(), f"{what}: expected a non-empty message, got {got_message!r}"

    _assert_no_such(_error(lambda: cf.get_distribution(Id=dist_id)), "GetDistribution after delete")
    listed = [
        d.get("Id")
        for page in cf.get_paginator("list_distributions").paginate()
        for d in page.get("DistributionList", {}).get("Items", []) or []
    ]
    assert dist_id not in listed, f"deleted distribution {dist_id} is still listed by ListDistributions"
    _assert_no_such(
        _error(lambda: cf.update_distribution(Id=dist_id, IfMatch=final_etag, DistributionConfig=cfg)),
        "UpdateDistribution on the deleted id",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
