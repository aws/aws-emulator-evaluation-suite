"""distribution-if-match-omitted-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
_COUNTER = itertools.count()
_IF_MATCH_INVALID = "The If-Match version is missing or not valid for the resource."

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    """Run fn and return the ClientError (code, message). An unexpected SUCCESS raises,
    because an emulator accepting input real AWS refuses is the strongest signal
    available and must not be reported as a code mismatch."""
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
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real-behav", "Value": "if-match-omitted"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


# ===== end helpers =====

CHECK = "distribution-if-match-omitted-rejected"
GROUP = 'distribution-errors'
SERVICES = ['cloudfront']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Omitting If-Match on UpdateDistribution or DeleteDistribution fails with InvalidIfMatchVersion
    (IfMatch is optional in the model, so the service must refuse), while a control update holding
    the current ETag succeeds.
    """
    cf = ctx.client("cloudfront")
    created = _create_distribution(cf, ctx, comment="sim2real if-match-omitted")
    dist_id = created["Distribution"]["Id"]

    before = cf.get_distribution_config(Id=dist_id)
    etag_before = before["ETag"]
    cfg = before["DistributionConfig"]
    original_comment = cfg["Comment"]

    # 1. UpdateDistribution with NO If-Match header at all.
    cfg["Comment"] = "sim2real if-match-omitted UPDATED"
    code, message = _error(lambda: cf.update_distribution(Id=dist_id, DistributionConfig=cfg))
    assert code == "InvalidIfMatchVersion", (
        f"UpdateDistribution without If-Match must fail with InvalidIfMatchVersion, got {code}"
    )
    assert message == _IF_MATCH_INVALID, f"expected message {_IF_MATCH_INVALID!r}, got {message!r}"

    # ...and the effect must be absent: neither the config nor the ETag moved.
    after_update = cf.get_distribution_config(Id=dist_id)
    assert after_update["DistributionConfig"]["Comment"] == original_comment, (
        "a rejected If-Match-less update must not mutate the config; Comment is now "
        f"{after_update['DistributionConfig']['Comment']!r}, expected {original_comment!r}"
    )
    assert after_update["ETag"] == etag_before, (
        f"a rejected update must not rotate the ETag: {etag_before} -> {after_update['ETag']}"
    )

    # 2. DeleteDistribution with NO If-Match header. The distribution is already
    #    Enabled=False, so the ONLY thing wrong with this request is the missing
    #    version token — a DistributionNotDisabled answer would be the wrong code.
    code, message = _error(lambda: cf.delete_distribution(Id=dist_id))
    assert code == "InvalidIfMatchVersion", (
        f"DeleteDistribution without If-Match must fail with InvalidIfMatchVersion, got {code}"
    )
    assert message == _IF_MATCH_INVALID, f"expected message {_IF_MATCH_INVALID!r}, got {message!r}"

    # ...and the distribution must still exist.
    still = cf.get_distribution(Id=dist_id)
    assert still["Distribution"]["Id"] == dist_id, (
        "a rejected If-Match-less delete must leave the distribution in place"
    )

    # 3. Control case: the identical update WITH the current ETag is accepted and
    #    rotates the ETag, proving the two rejections were about If-Match only.
    updated = cf.update_distribution(
        Id=dist_id, IfMatch=etag_before, DistributionConfig=cfg
    )
    assert updated["Distribution"]["DistributionConfig"]["Comment"] == (
        "sim2real if-match-omitted UPDATED"
    ), updated["Distribution"]["DistributionConfig"]["Comment"]
    assert updated["ETag"] != etag_before, (
        f"a successful update must rotate the ETag away from {etag_before}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
