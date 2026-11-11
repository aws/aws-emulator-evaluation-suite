"""distribution-update-malformed-etag-invalid."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
_IF_MATCH_INVALID = "The If-Match version is missing or not valid for the resource."

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp

CHECK = "distribution-update-malformed-etag-invalid"
GROUP = 'distribution-errors'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A garbage-format If-Match value is rejected with InvalidIfMatchVersion, distinct from staleness."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="malformed-etag")
    dist_id = resp["Distribution"]["Id"]
    _wait_distribution_deployed(cf, dist_id)

    before = cf.get_distribution_config(Id=dist_id)
    etag_before = before["ETag"]
    cfg = before["DistributionConfig"]
    original_comment = cfg["Comment"]
    cfg["Comment"] = "malformed-etag UPDATED"

    code, message = _error(lambda: cf.update_distribution(
        Id=dist_id, IfMatch="not-a-real-etag-format", DistributionConfig=cfg))
    assert code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {code}"
    assert message == _IF_MATCH_INVALID, f"expected message {_IF_MATCH_INVALID!r}, got {message!r}"

    # the rejected update must not have mutated anything: neither config nor ETag moved
    after = cf.get_distribution_config(Id=dist_id)
    assert after["DistributionConfig"]["Comment"] == original_comment, (
        "a rejected malformed-If-Match update must not mutate the config; Comment is now "
        f"{after['DistributionConfig']['Comment']!r}, expected {original_comment!r}"
    )
    assert after["ETag"] == etag_before, (
        f"a rejected update must not rotate the ETag: {etag_before} -> {after['ETag']}"
    )

    # positive control: the identical update WITH the current, well-formed ETag is
    # accepted, proving the rejection above was specifically about the malformed
    # If-Match value and not about the request body or the distribution's state
    updated = cf.update_distribution(Id=dist_id, IfMatch=etag_before, DistributionConfig=cfg)
    assert updated["Distribution"]["DistributionConfig"]["Comment"] == "malformed-etag UPDATED", (
        updated["Distribution"]["DistributionConfig"]["Comment"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
