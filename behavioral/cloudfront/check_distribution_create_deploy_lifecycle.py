"""distribution-create-deploy-lifecycle."""
from __future__ import annotations

import re
import time
import itertools

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

CHECK = "distribution-create-deploy-lifecycle"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created distribution transitions InProgress -> Deployed and exposes a domain name/ARN."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="fidelity-lifecycle")
    dist = resp["Distribution"]
    dist_id = dist["Id"]

    assert dist["Status"] == "InProgress", f"expected initial status InProgress, got {dist['Status']}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", dist.get("DomainName", "")), (
        f"expected a hostname DomainName to be assigned at creation, got {dist.get('DomainName')!r}"
    )
    assert dist.get("ARN", "").endswith(dist_id), "ARN should reference the distribution id"

    _wait_distribution_deployed(cf, dist_id)

    final = cf.get_distribution(Id=dist_id)["Distribution"]
    assert final["Status"] == "Deployed", f"expected Deployed after polling, got {final['Status']}"

    listing = cf.list_distributions()["DistributionList"].get("Items", [])
    ids = [d["Id"] for d in listing]
    assert dist_id in ids, "created distribution should appear in ListDistributions"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
