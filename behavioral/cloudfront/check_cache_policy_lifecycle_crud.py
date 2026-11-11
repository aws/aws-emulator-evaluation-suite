"""cache-policy-lifecycle-crud."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (code, message, HTTP status). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; an already-deleted one is done."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchCachePolicy":
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

CHECK = "cache-policy-lifecycle-crud"
GROUP = 'policies'
SERVICES = ['cloudfront']


def _assert_no_such(result, what):
    """NoSuchCachePolicy, HTTP 404 and a non-empty message (AWS's message names no id)."""
    code, message, status = result
    assert code == "NoSuchCachePolicy", f"{what}: expected NoSuchCachePolicy, got {code}"
    assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
    assert (message or "").strip(), f"{what}: expected a non-empty message, got {message!r}"

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Custom cache policy CRUD: create with explicit TTLs, update MinTTL, delete; the dead policy
    is unreadable, unlisted and unmutable."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-cp-")
    created = cf.create_cache_policy(CachePolicyConfig={
        "Name": name,
        "Comment": "fidelity cache policy",
        "DefaultTTL": 100,
        "MaxTTL": 200,
        "MinTTL": 10,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })
    policy_id = created["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_cache_policy, cf.delete_cache_policy, policy_id))
    created_min_ttl = created["CachePolicy"]["CachePolicyConfig"]["MinTTL"]
    assert created_min_ttl == 10, f"expected MinTTL 10 on create, got {created_min_ttl}"

    got = cf.get_cache_policy(Id=policy_id)
    cfg = got["CachePolicy"]["CachePolicyConfig"]
    cfg["MinTTL"] = 20
    updated = cf.update_cache_policy(Id=policy_id, IfMatch=got["ETag"], CachePolicyConfig=cfg)
    assert updated["CachePolicy"]["CachePolicyConfig"]["MinTTL"] == 20, "MinTTL update must persist"

    refetched = cf.get_cache_policy(Id=policy_id)
    refetched_min_ttl = refetched["CachePolicy"]["CachePolicyConfig"]["MinTTL"]
    assert refetched_min_ttl == 20, f"expected MinTTL 20 on an independent read after update, got {refetched_min_ttl}"
    cf.delete_cache_policy(Id=policy_id, IfMatch=refetched["ETag"])

    # Beat 1: the by-id read is NoSuchCachePolicy 404.
    _assert_no_such(_error(lambda: cf.get_cache_policy(Id=policy_id)), "GetCachePolicy after delete")

    # Beat 2: the policy is absent from the custom-policy listing.
    listed, marker = [], None
    while True:
        page = cf.list_cache_policies(Type="custom", **({"Marker": marker} if marker else {}))["CachePolicyList"]
        listed += [i["CachePolicy"]["Id"] for i in page.get("Items", []) or []]
        marker = page.get("NextMarker")
        if not marker:
            break
    assert policy_id not in listed, f"deleted cache policy {policy_id} is still listed by ListCachePolicies"

    # Beat 3: a mutation on the dead id fails the same way a read does.
    _assert_no_such(
        _error(lambda: cf.update_cache_policy(Id=policy_id, IfMatch=refetched["ETag"], CachePolicyConfig=cfg)),
        "UpdateCachePolicy on the deleted id",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
