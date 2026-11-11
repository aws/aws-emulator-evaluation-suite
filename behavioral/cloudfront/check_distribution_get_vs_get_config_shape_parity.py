"""distribution-get-vs-get-config-shape-parity."""
from __future__ import annotations

import itertools
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


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
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": cfg,
            "Tags": {"Items": [{"Key": "sim2real-behav", "Value": "shape-parity"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


CHECK = "distribution-get-vs-get-config-shape-parity"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistribution returns the Distribution envelope and GetDistributionConfig the bare config,
    with an identical nested config and one shared ETag that UpdateDistribution accepts as IfMatch.
    The distribution ARN has an empty region field (CloudFront is global)."""
    cf = ctx.client("cloudfront")
    created = _create_distribution(cf, ctx, comment="sim2real shape-parity")
    dist_id = created["Distribution"]["Id"]

    full = cf.get_distribution(Id=dist_id)
    bare = cf.get_distribution_config(Id=dist_id)

    dist = full["Distribution"]
    for field in ("Id", "ARN", "Status", "LastModifiedTime", "DomainName",
                  "InProgressInvalidationBatches", "DistributionConfig"):
        assert field in dist, f"GetDistribution must return Distribution.{field}, got {sorted(dist)}"
    assert dist["Status"] in ("InProgress", "Deployed"), dist["Status"]
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", dist["DomainName"]), dist["DomainName"]
    # CloudFront is global: arn:aws:cloudfront::<account>:distribution/<id> — no region.
    assert dist["ARN"].startswith("arn:") and ":cloudfront::" in dist["ARN"], (
        f"CloudFront ARNs are global and carry an empty region field, got {dist['ARN']!r}"
    )
    assert dist["ARN"].endswith(f":distribution/{dist_id}"), dist["ARN"]

    # GetDistributionConfig must NOT carry the Distribution envelope or its metadata.
    assert "Distribution" not in bare, (
        f"GetDistributionConfig must not return a Distribution wrapper, got {sorted(bare)}"
    )
    bare_cfg = bare["DistributionConfig"]
    for leaked in ("Id", "ARN", "Status", "DomainName", "LastModifiedTime",
                   "InProgressInvalidationBatches"):
        assert leaked not in bare_cfg, (
            f"GetDistributionConfig leaked server-owned field {leaked!r} into "
            f"DistributionConfig: {sorted(bare_cfg)}"
        )

    # The nested config and the bare config are the same document.
    assert dist["DistributionConfig"] == bare_cfg, (
        "Distribution.DistributionConfig and GetDistributionConfig.DistributionConfig "
        "must be identical"
    )

    # One version token for both ops.
    assert full["ETag"] == bare["ETag"], (
        f"GetDistribution ETag {full['ETag']} != GetDistributionConfig ETag {bare['ETag']}"
    )

    # The SDK read-modify-write pattern: GetDistributionConfig -> mutate -> UpdateDistribution.
    bare_cfg["Comment"] = "sim2real shape-parity UPDATED"
    updated = cf.update_distribution(
        Id=dist_id, IfMatch=bare["ETag"], DistributionConfig=bare_cfg
    )
    new_etag = updated["ETag"]
    assert new_etag != bare["ETag"], "a successful update must rotate the ETag"

    # Both ops now agree on the NEW token, and both see the new config.
    assert cf.get_distribution(Id=dist_id)["ETag"] == new_etag, (
        "GetDistribution must report the post-update ETag"
    )
    refetched = cf.get_distribution_config(Id=dist_id)
    assert refetched["ETag"] == new_etag, (
        "GetDistributionConfig must report the same post-update ETag as GetDistribution"
    )
    assert refetched["DistributionConfig"]["Comment"] == "sim2real shape-parity UPDATED", (
        refetched["DistributionConfig"]["Comment"]
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
