"""distribution-duplicate-caller-reference-conflict."""
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

def _list_distribution_ids(cf):
    """Walk ListDistributions completely; an independent read distinct from CreateDistribution."""
    ids = []
    marker = None
    for _ in range(30):
        kwargs = {"MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions(**kwargs)
        listing = resp["DistributionList"]
        ids.extend(item["Id"] for item in listing.get("Items") or [])
        if listing.get("IsTruncated") and listing.get("NextMarker"):
            marker = listing["NextMarker"]
        else:
            break
    return ids

CHECK = "distribution-duplicate-caller-reference-conflict"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution reusing a CallerReference with a different config is refused with
    DistributionAlreadyExists naming the existing id and creates nothing, while replaying the original
    config under the same CallerReference returns the same distribution without a duplicate."""
    cf = ctx.client("cloudfront")
    caller_ref = _caller_reference(ctx, "dup-ref")
    cfg1 = _minimal_distribution_config(ctx, comment="original")
    cfg1["CallerReference"] = caller_ref

    created = cf.create_distribution(DistributionConfig=cfg1)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    # Positive control: CreateDistribution works, and the CallerReference the next call collides
    # with was accepted.
    assert created["Distribution"]["DistributionConfig"]["CallerReference"] == caller_ref, (
        "CreateDistribution must echo back the CallerReference it was given"
    )

    cfg2 = _minimal_distribution_config(ctx, comment="different-config")
    cfg2["CallerReference"] = caller_ref  # same reference, different Comment/Origins

    try:
        conflicting = cf.create_distribution(DistributionConfig=cfg2)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "DistributionAlreadyExists", f"expected DistributionAlreadyExists, got {code}"
        expected_message = (
            "The caller reference that you are using to create a distribution is associated with "
            f"another distribution. Already exists: {dist_id}"
        )
        assert message == expected_message, f"unexpected DistributionAlreadyExists message: {message!r}"
    else:
        # An over-permissive target created a second distribution: it must still be torn down,
        # and the accepted call is the failure, not a code mismatch.
        leaked_id = conflicting["Distribution"]["Id"]
        ctx.on_cleanup(lambda: _force_delete_distribution(cf, leaked_id))
        raise AssertionError(
            f"expected DistributionAlreadyExists, but a second distribution {leaked_id} was created"
        )

    # Effect absent, via an independent read (ListDistributions, not CreateDistribution's own
    # response): the rejected attempt must not be visible anywhere.
    ids_after_conflict = _list_distribution_ids(cf)
    assert ids_after_conflict.count(dist_id) == 1, (
        f"expected exactly one distribution {dist_id} after the rejected duplicate, "
        f"saw it {ids_after_conflict.count(dist_id)} times"
    )

    # Restore: the SAME CallerReference with the ORIGINAL, byte-identical config is CloudFront's
    # documented idempotent replay, and must succeed — proving the earlier rejection was about the
    # mismatched config, not a blanket ban on reusing this CallerReference.
    replayed = cf.create_distribution(DistributionConfig=cfg1)
    assert replayed["Distribution"]["Id"] == dist_id, (
        "replaying the identical CallerReference+config must return the SAME distribution, "
        f"got {replayed['Distribution']['Id']} instead of {dist_id}"
    )
    assert replayed["Distribution"]["ARN"] == created["Distribution"]["ARN"]

    # Terminal read: independent of both CreateDistribution calls, proving the idempotent replay
    # did not silently create a duplicate either.
    ids_after_replay = _list_distribution_ids(cf)
    assert ids_after_replay.count(dist_id) == 1, (
        f"expected exactly one distribution {dist_id} after the idempotent replay, "
        f"saw it {ids_after_replay.count(dist_id)} times"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
