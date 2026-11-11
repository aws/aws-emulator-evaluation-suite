"""list-distributions-by-cache-policy-id-consistency."""
from __future__ import annotations

import time
import itertools
from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

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

def _minimal_cache_policy_config(name, **overrides):
    cfg = {
        "Comment": "behavioral test cache policy",
        "Name": name,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "MinTTL": 1,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }
    cfg.update(overrides)
    return cfg

def _delete_cache_policy(cf, policy_id):
    try:
        etag = cf.get_cache_policy(Id=policy_id)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchCachePolicy":
            return
        raise
    cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

CHECK = "list-distributions-by-cache-policy-id-consistency"
GROUP = 'distribution-associations'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByCachePolicyId must reflect a distribution whose
    DefaultCacheBehavior references a custom CachePolicy — and must stop
    reflecting it once the distribution is deleted."""
    cf = ctx.client("cloudfront")
    cp_name = ctx.unique_name("sim2real-behav-cp-assoc-")
    cp_resp = cf.create_cache_policy(CachePolicyConfig=_minimal_cache_policy_config(cp_name))
    cp_id = cp_resp["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_cache_policy(cf, cp_id))

    cfg = _minimal_distribution_config(ctx, comment="cp-assoc")
    cfg["DefaultCacheBehavior"] = {
        "TargetOriginId": "primary-origin",
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": cp_id,
    }
    dist_resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = dist_resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    def _ids_by_cache_policy():
        return cf.list_distributions_by_cache_policy_id(CachePolicyId=cp_id)["DistributionIdList"]["Items"]

    ids = _poll_until(
        _ids_by_cache_policy,
        lambda ids: dist_id in ids,
        timeout_s=60,
        interval_s=3.0,
        description="distribution to appear in ListDistributionsByCachePolicyId",
    )
    assert dist_id in ids, f"expected {dist_id} in ListDistributionsByCachePolicyId, got {ids}"

    # A custom cache policy still attached to a distribution cannot be
    # deleted — verifies the association is enforced, not just reported.
    cp_etag = cf.get_cache_policy(Id=cp_id)["ETag"]
    code, message = _error_code_and_message(lambda: cf.delete_cache_policy(Id=cp_id, IfMatch=cp_etag))
    assert code == "CachePolicyInUse", f"expected CachePolicyInUse while attached, got {code}"
    expected = (
        "The specified cache policy is currently associated with a cache behavior. "
        "Please disassociate the policy before deleting."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    _force_delete_distribution(cf, dist_id)

    ids_after = _poll_until(
        _ids_by_cache_policy,
        lambda ids: dist_id not in ids,
        timeout_s=60,
        interval_s=3.0,
        description="distribution to disappear from ListDistributionsByCachePolicyId after delete",
    )
    assert dist_id not in ids_after, (
        f"expected {dist_id} removed from ListDistributionsByCachePolicyId after delete, "
        f"got {ids_after}"
    )

    # The delete-while-attached refusal above is a broken-then-restored
    # negative: once the attaching distribution is gone, the identical
    # delete call must now succeed (restore beat), proved by an
    # independent read of the policy as gone.
    cp_etag_after = cf.get_cache_policy(Id=cp_id)["ETag"]
    cf.delete_cache_policy(Id=cp_id, IfMatch=cp_etag_after)
    code_after_delete, message_after_delete = _error_code_and_message(lambda: cf.get_cache_policy(Id=cp_id))
    assert code_after_delete == "NoSuchCachePolicy", (
        f"expected NoSuchCachePolicy after cache policy delete, got {code_after_delete}"
    )
    assert message_after_delete == "The specified cache policy does not exist.", (
        f"unexpected message {message_after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
