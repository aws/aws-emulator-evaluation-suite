"""distribution-caller-reference-change-rejected."""
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
    """Run fn and return the ClientError (code, message); raise if it unexpectedly succeeded.

    An emulator ACCEPTING input real AWS refuses is the strongest signal available and
    must not be turned into a falsy code that merely mismatches the expected value.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected a ClientError but the call succeeded and returned {result!r}"
    )


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

CHECK = "distribution-caller-reference-change-rejected"
GROUP = 'distribution-errors'
SERVICES = ['cloudfront']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Changing the immutable CallerReference on UpdateDistribution fails with IllegalUpdate and does
    not persist, so a config stored as an opaque blob breaks the idempotency contract and fails.
    """
    cf = ctx.client("cloudfront")
    created = _create_distribution(cf, ctx, comment="sim2real caller-ref-immutable")
    dist_id = created["Distribution"]["Id"]

    before = cf.get_distribution_config(Id=dist_id)
    etag = before["ETag"]
    cfg = before["DistributionConfig"]
    original_ref = cfg["CallerReference"]
    assert original_ref, "CreateDistribution must echo back the CallerReference"

    # Break exactly one thing: a brand-new CallerReference, everything else identical.
    mutated = dict(cfg)
    mutated["CallerReference"] = _caller_reference(ctx, prefix="ref-changed")
    code, message = _error_code(
        lambda: cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=mutated)
    )
    assert code == "IllegalUpdate", (
        "changing CallerReference on UpdateDistribution must fail with IllegalUpdate, "
        f"got {code}"
    )
    assert message == "The caller reference cannot be modified.", (
        f"UpdateDistribution IllegalUpdate message: {message!r}"
    )

    # Effect absent: the stored CallerReference and the ETag are untouched.
    after = cf.get_distribution_config(Id=dist_id)
    assert after["DistributionConfig"]["CallerReference"] == original_ref, (
        "a rejected update must not mutate CallerReference: "
        f"{original_ref!r} -> {after['DistributionConfig']['CallerReference']!r}"
    )
    assert after["ETag"] == etag, (
        f"a rejected update must not rotate the ETag: {etag} -> {after['ETag']}"
    )

    # Control: the same request with the ORIGINAL CallerReference and a changed
    # mutable field is accepted, so the rejection was about immutability only.
    cfg["Comment"] = "sim2real caller-ref-immutable OK"
    ok = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    assert ok["Distribution"]["DistributionConfig"]["CallerReference"] == original_ref, (
        "a successful update must still report the original CallerReference"
    )
    assert ok["Distribution"]["DistributionConfig"]["Comment"] == (
        "sim2real caller-ref-immutable OK"
    ), ok["Distribution"]["DistributionConfig"]["Comment"]

    # Independent read at the destination: the accepted update actually persisted,
    # not just an echo from the mutating call's own response.
    final = cf.get_distribution_config(Id=dist_id)
    assert final["DistributionConfig"]["CallerReference"] == original_ref, (
        "CallerReference must remain unchanged after the accepted control update: "
        f"{original_ref!r} -> {final['DistributionConfig']['CallerReference']!r}"
    )
    assert final["DistributionConfig"]["Comment"] == "sim2real caller-ref-immutable OK", (
        "the accepted Comment change must persist and be independently readable, got "
        f"{final['DistributionConfig']['Comment']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
