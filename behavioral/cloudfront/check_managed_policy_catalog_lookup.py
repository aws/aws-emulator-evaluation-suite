"""managed-policy-catalog-lookup."""
from __future__ import annotations

from behavioral_harness import tags

# The documented id of Managed-CachingOptimized; other managed policies are asserted by
# name plus cross-operation consistency rather than by id.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _list_all(list_fn, list_key, **kwargs):
    """Drain a CloudFront Marker/NextMarker list into a flat Items list."""
    items = []
    marker = None
    while True:
        call = dict(kwargs)
        call["MaxItems"] = "100"
        if marker:
            call["Marker"] = marker
        page = list_fn(**call)[list_key]
        items.extend(page.get("Items", []) or [])
        marker = page.get("NextMarker")
        if not marker:
            return items


CHECK = "managed-policy-catalog-lookup"
GROUP = 'policies'
SERVICES = ['cloudfront']

# Documented managed policies; templates reference them by name, so the names are stable.
REQUIRED_CACHE_POLICIES = {"Managed-CachingOptimized", "Managed-CachingDisabled"}
REQUIRED_ORIGIN_REQUEST_POLICIES = {"Managed-AllViewer", "Managed-CORS-S3Origin"}
REQUIRED_RESPONSE_HEADERS_POLICIES = {"Managed-SimpleCORS", "Managed-SecurityHeadersPolicy"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Managed cache, origin-request and response-headers policies are listed under Type=managed,
    disjoint from Type=custom, consistent across List/Get/GetConfig, with documented ids and TTLs.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-managed-cache-policies.html
    """
    cf = ctx.client("cloudfront")

    # ---- cache policies -------------------------------------------------
    managed = _list_all(cf.list_cache_policies, "CachePolicyList", Type="managed")
    assert managed, "ListCachePolicies(Type='managed') must not be empty"
    by_name = {}
    for item in managed:
        assert item.get("Type") == "managed", (
            f"every item under Type='managed' must report Type='managed', got {item.get('Type')}"
        )
        cfg = item["CachePolicy"]["CachePolicyConfig"]
        by_name[cfg["Name"]] = item["CachePolicy"]["Id"]
    missing = REQUIRED_CACHE_POLICIES - set(by_name)
    assert not missing, (
        f"managed cache policies missing from the catalog: {sorted(missing)} "
        f"(present: {sorted(by_name)})"
    )
    assert by_name["Managed-CachingOptimized"] == MANAGED_CACHING_OPTIMIZED, (
        "Managed-CachingOptimized must keep its documented id "
        f"{MANAGED_CACHING_OPTIMIZED}, got {by_name['Managed-CachingOptimized']}"
    )

    # Managed and custom partitions are disjoint.
    custom_ids = {
        item["CachePolicy"]["Id"]
        for item in _list_all(cf.list_cache_policies, "CachePolicyList", Type="custom")
    }
    overlap = custom_ids & set(by_name.values())
    assert not overlap, (
        f"managed cache policies must not appear under Type='custom', found {sorted(overlap)}"
    )

    # Get / GetConfig / List agree, for every managed policy.
    for name, policy_id in by_name.items():
        got = cf.get_cache_policy(Id=policy_id)
        assert got["CachePolicy"]["Id"] == policy_id, got["CachePolicy"]["Id"]
        assert got["CachePolicy"]["CachePolicyConfig"]["Name"] == name, (
            f"GetCachePolicy({policy_id}) reported "
            f"{got['CachePolicy']['CachePolicyConfig']['Name']!r}, List said {name!r}"
        )
        cfg_only = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
        assert cfg_only == got["CachePolicy"]["CachePolicyConfig"], (
            f"GetCachePolicyConfig and GetCachePolicy disagree on the body of {name}"
        )

    # The managed bodies carry the documented semantics, not just the ids.
    disabled = cf.get_cache_policy_config(Id=by_name["Managed-CachingDisabled"])[
        "CachePolicyConfig"
    ]
    assert (disabled["MinTTL"], disabled["DefaultTTL"], disabled["MaxTTL"]) == (0, 0, 0), (
        "Managed-CachingDisabled must have all three TTLs at 0, got "
        f"{(disabled['MinTTL'], disabled['DefaultTTL'], disabled['MaxTTL'])}"
    )
    optimized = cf.get_cache_policy_config(Id=MANAGED_CACHING_OPTIMIZED)["CachePolicyConfig"]
    assert (optimized["MinTTL"], optimized["DefaultTTL"], optimized["MaxTTL"]) == (
        1,
        86400,
        31536000,
    ), (
        "Managed-CachingOptimized must have TTLs 1/86400/31536000, got "
        f"{(optimized['MinTTL'], optimized['DefaultTTL'], optimized['MaxTTL'])}"
    )

    # An untyped list is the union of both partitions.
    all_ids = {
        item["CachePolicy"]["Id"] for item in _list_all(cf.list_cache_policies, "CachePolicyList")
    }
    assert set(by_name.values()) <= all_ids, (
        "ListCachePolicies with no Type filter must include the managed policies; missing "
        f"{sorted(set(by_name.values()) - all_ids)}"
    )

    # ---- origin request policies ---------------------------------------
    orp_managed = _list_all(
        cf.list_origin_request_policies, "OriginRequestPolicyList", Type="managed"
    )
    orp_by_name = {}
    for item in orp_managed:
        assert item.get("Type") == "managed", item.get("Type")
        orp = item["OriginRequestPolicy"]
        orp_by_name[orp["OriginRequestPolicyConfig"]["Name"]] = orp["Id"]
    missing = REQUIRED_ORIGIN_REQUEST_POLICIES - set(orp_by_name)
    assert not missing, (
        f"managed origin request policies missing: {sorted(missing)} "
        f"(present: {sorted(orp_by_name)})"
    )
    orp_custom_ids = {
        item["OriginRequestPolicy"]["Id"]
        for item in _list_all(
            cf.list_origin_request_policies, "OriginRequestPolicyList", Type="custom"
        )
    }
    overlap = orp_custom_ids & set(orp_by_name.values())
    assert not overlap, (
        f"managed origin request policies must not appear under Type='custom': {sorted(overlap)}"
    )
    for name, policy_id in orp_by_name.items():
        got = cf.get_origin_request_policy(Id=policy_id)["OriginRequestPolicy"]
        assert got["OriginRequestPolicyConfig"]["Name"] == name, (
            f"GetOriginRequestPolicy({policy_id}) reported "
            f"{got['OriginRequestPolicyConfig']['Name']!r}, List said {name!r}"
        )

    # ---- response headers policies -------------------------------------
    rhp_managed = _list_all(
        cf.list_response_headers_policies, "ResponseHeadersPolicyList", Type="managed"
    )
    rhp_by_name = {}
    for item in rhp_managed:
        assert item.get("Type") == "managed", item.get("Type")
        rhp = item["ResponseHeadersPolicy"]
        rhp_by_name[rhp["ResponseHeadersPolicyConfig"]["Name"]] = rhp["Id"]
    missing = REQUIRED_RESPONSE_HEADERS_POLICIES - set(rhp_by_name)
    assert not missing, (
        f"managed response headers policies missing: {sorted(missing)} "
        f"(present: {sorted(rhp_by_name)})"
    )
    rhp_custom_ids = {
        item["ResponseHeadersPolicy"]["Id"]
        for item in _list_all(
            cf.list_response_headers_policies, "ResponseHeadersPolicyList", Type="custom"
        )
    }
    overlap = rhp_custom_ids & set(rhp_by_name.values())
    assert not overlap, (
        f"managed response headers policies must not appear under Type='custom': {sorted(overlap)}"
    )
    for name, policy_id in rhp_by_name.items():
        got = cf.get_response_headers_policy(Id=policy_id)["ResponseHeadersPolicy"]
        assert got["ResponseHeadersPolicyConfig"]["Name"] == name, (
            f"GetResponseHeadersPolicy({policy_id}) reported "
            f"{got['ResponseHeadersPolicyConfig']['Name']!r}, List said {name!r}"
        )

    # The managed catalogs are non-empty in every account.
    assert orp_managed and rhp_managed, (
        "the managed origin-request and response-headers catalogs must both be non-empty"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
