"""distribution-disable-then-delete-removes-resource."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()
#: CloudFront propagation waits, sized from the CloudFront (long) service-class budget.
_LONG_BUDGET_S = 1700

def _error(fn):
    """Call fn(); return its (code, message, HTTP status). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=_LONG_BUDGET_S, interval_s=15, etag_hint=None):
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
            return  # the check itself deleted it
        raise
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
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real-owner", "Value": "behavioral-check"}]},
    )
    return resp

CHECK = "distribution-disable-then-delete-removes-resource"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution created disabled reaches Deployed and reads back as created; once deleted it is
    NoSuchDistribution to GetDistribution and to a second DeleteDistribution and absent from
    ListDistributions."""
    cf = ctx.client("cloudfront")
    resp = _create_distribution(cf, ctx, comment="teardown-flow", enabled=False)
    dist_id = resp["Distribution"]["Id"]
    assert resp["Distribution"]["DistributionConfig"]["Enabled"] is False, (
        f"expected the distribution to be created disabled, got {resp['Distribution']['DistributionConfig']['Enabled']!r}"
    )

    etag = _wait_distribution_deployed(cf, dist_id)

    # Independent read before delete: the stored config is what was created.
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    stored = cfg_resp["DistributionConfig"]
    assert stored.get("Comment") == "teardown-flow", f"expected Comment 'teardown-flow', got {stored.get('Comment')!r}"
    assert stored.get("Enabled") is False, f"expected the stored config disabled, got {stored.get('Enabled')!r}"
    expected_arn = f"arn:aws:cloudfront::{ctx.account}:distribution/{dist_id}"
    assert resp["Distribution"].get("ARN") == expected_arn, (
        f"expected distribution ARN {expected_arn!r}, got {resp['Distribution'].get('ARN')!r}"
    )
    etag = cfg_resp["ETag"]

    cf.delete_distribution(Id=dist_id, IfMatch=etag)

    def _assert_no_such(result, what):
        code, message, status = result
        assert code == "NoSuchDistribution", f"{what}: expected NoSuchDistribution, got {code}"
        assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status!r}"
        assert (message or "").strip(), f"{what}: expected a non-empty message, got {message!r}"

    # The by-id read is NoSuchDistribution 404.
    _assert_no_such(_error(lambda: cf.get_distribution(Id=dist_id)), "GetDistribution after delete")

    # The id is absent from the full (paginated) listing.
    listed = [
        d.get("Id")
        for page in cf.get_paginator("list_distributions").paginate()
        for d in page.get("DistributionList", {}).get("Items", []) or []
    ]
    assert dist_id not in listed, f"deleted distribution {dist_id} is still listed by ListDistributions"

    # A mutation on the deleted id is refused the same way: a second delete on it.
    _assert_no_such(
        _error(lambda: cf.delete_distribution(Id=dist_id, IfMatch=etag)),
        "DeleteDistribution on the deleted id",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
