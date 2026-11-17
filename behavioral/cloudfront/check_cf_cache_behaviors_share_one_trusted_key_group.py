"""cf-cache-behaviors-share-one-trusted-key-group."""
from __future__ import annotations

import itertools
import time

from behavioral_harness import tags

_COUNTER = itertools.count()

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
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


def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])


def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"


def _generate_rsa_public_key_pem():
    """Fresh, structurally-valid RSA-2048 SPKI PEM for CreatePublicKey."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _s3_origin(origin_id: str, domain: str) -> dict:
    """A minimal S3-backed Origin; the bucket need not exist for config CRUD."""
    return {
        "Id": origin_id,
        "DomainName": domain,
        "S3OriginConfig": {"OriginAccessIdentity": ""},
    }


def _cache_behavior(path_pattern, origin_id, key_group_id):
    return {
        "PathPattern": path_pattern,
        "TargetOriginId": origin_id,
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
    }


CHECK = "cf-cache-behaviors-share-one-trusted-key-group"
GROUP = "security"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution whose default and four additional cache behaviors all trust the same key
    group is created, and GetDistribution reports one active trusted key group, not five -- the
    per-distribution accounting counts distinct key groups, not cache-behavior references."""
    cf = ctx.client("cloudfront")

    created_key = cf.create_public_key(PublicKeyConfig={
        "CallerReference": _caller_reference(ctx, "pk"),
        "Name": ctx.unique_name("sim2real-behav-pk-"),
        "EncodedKey": _generate_rsa_public_key_pem(),
    })
    key_id = created_key["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

    created_group = cf.create_key_group(KeyGroupConfig={
        "Name": ctx.unique_name("sim2real-behav-kg-"),
        "Items": [key_id],
    })
    group_id = created_group["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_key_group, cf.delete_key_group, group_id))

    origin_id = "shared-origin"
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.s3.us-east-1.amazonaws.com"
    extra_patterns = ["/a/*", "/b/*", "/c/*", "/d/*"]
    cfg = {
        "CallerReference": _caller_reference(ctx, "trust"),
        "Comment": "sim2real shared trusted key group",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [_s3_origin(origin_id, domain)]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [group_id]},
        },
        "CacheBehaviors": {
            "Quantity": len(extra_patterns),
            "Items": [_cache_behavior(p, origin_id, group_id) for p in extra_patterns],
        },
    }
    created = cf.create_distribution(DistributionConfig=cfg)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    # Every one of the five cache behaviors stores the shared key group, in the immediate response.
    created_cfg = created["Distribution"]["DistributionConfig"]
    assert created_cfg["DefaultCacheBehavior"]["TrustedKeyGroups"]["Items"] == [group_id], (
        created_cfg["DefaultCacheBehavior"]["TrustedKeyGroups"]
    )
    created_items = created_cfg["CacheBehaviors"]["Items"]
    assert created_cfg["CacheBehaviors"]["Quantity"] == 4, created_cfg["CacheBehaviors"]
    for item in created_items:
        assert item["TrustedKeyGroups"]["Items"] == [group_id], item["TrustedKeyGroups"]

    _wait_distribution_deployed(cf, dist_id)

    # GetDistributionConfig persists the same five-way reference to the one key group.
    got_cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assert got_cfg["DefaultCacheBehavior"]["TrustedKeyGroups"]["Items"] == [group_id], (
        got_cfg["DefaultCacheBehavior"]["TrustedKeyGroups"]
    )
    got_patterns = {b["PathPattern"]: b["TrustedKeyGroups"]["Items"] for b in got_cfg["CacheBehaviors"]["Items"]}
    assert got_patterns == {p: [group_id] for p in extra_patterns}, got_patterns

    # The distribution-level active set counts the key group ONCE: five references to the same
    # key group collapse to one entry, which is the distinctness the per-distribution limit uses.
    dist = cf.get_distribution(Id=dist_id)["Distribution"]
    active = dist["ActiveTrustedKeyGroups"]
    assert active["Enabled"] is True, active
    assert active["Quantity"] == 1, (
        f"five cache behaviors reference the same key group, so ActiveTrustedKeyGroups must "
        f"report one distinct entry, got Quantity={active['Quantity']!r} Items={active['Items']!r}"
    )
    assert [g["KeyGroupId"] for g in active["Items"]] == [group_id], active["Items"]
    assert active["Items"][0]["KeyPairIds"] == {"Quantity": 1, "Items": [key_id]}, (
        active["Items"][0]["KeyPairIds"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
