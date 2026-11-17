"""managed-cache-policy-amplify-family-settings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-cache-policy-amplify-family-settings"
GROUP = "policies"
SERVICES = ["cloudfront"]

# Every Amplify-prefixed managed cache policy, by its documented id, and the exact
# ParametersInCacheKeyAndForwardedToOrigin shape CloudFront returns for it. Sets, not lists,
# stand in for Headers/Cookies/QueryStrings Items because CloudFront does not order them.
_AMPLIFY_CACHE_POLICIES = {
    "Managed-Amplify": {
        "id": "2e54312d-136d-493c-8eb9-b001f22f67d2",
        "ttls": (2, 2, 600),
        "cookies": "all",
        "headers": frozenset({"Authorization", "CloudFront-Viewer-Country", "Host"}),
        "query_strings": "all",
    },
    "Managed-Amplify-Default": {
        "id": "4d1d2f1d-3a71-49ad-9e08-7ea5d843a556",
        "ttls": (0, 0, 31536000),
        "cookies": "all",
        "headers": frozenset({"Authorization", "Accept", "CloudFront-Viewer-Country", "Host"}),
        "query_strings": "all",
    },
    "Managed-Amplify-Default-V2": {
        "id": "1b1c9610-973a-4fb9-9932-a6c274840887",
        "ttls": (0, 0, 31536000),
        "cookies": "all",
        "headers": frozenset(
            {"Authorization", "RSC", "Accept", "CloudFront-Viewer-Country", "X-Amplify-Dpl", "Host"}
        ),
        "query_strings": "all",
    },
    "Managed-Amplify-DefaultNoCookies": {
        "id": "a6bad946-36c3-4c33-aa98-362c74a7fb13",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset(),
        "headers": frozenset({"Authorization", "Accept", "CloudFront-Viewer-Country", "Host"}),
        "query_strings": "all",
    },
    "Managed-Amplify-DefaultNoCookies-V2": {
        "id": "17322e93-4707-445a-93bc-6c8c16621822",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset({"__dpl"}),
        "headers": frozenset(
            {"Authorization", "RSC", "Accept", "CloudFront-Viewer-Country", "X-Amplify-Dpl", "Host"}
        ),
        "query_strings": "all",
    },
    "Managed-Amplify-StaticContent": {
        "id": "7e5fad67-ee98-4ad0-b05a-394999eefc1a",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset(),
        "headers": frozenset({"Authorization", "Host"}),
        "query_strings": frozenset(),
    },
    "Managed-Amplify-StaticContent-V2": {
        "id": "4c02794c-7c81-4ba1-8b5d-e05fb0f95ed8",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset({"__dpl"}),
        "headers": frozenset(
            {"Authorization", "RSC", "CloudFront-Viewer-Country", "X-Amplify-Dpl", "Host"}
        ),
        "query_strings": frozenset({"dpl"}),
    },
    "Managed-Amplify-ImageOptimization": {
        "id": "1c6db51a-a33f-469a-8245-dae26771f530",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset(),
        "headers": frozenset({"Authorization", "Accept", "Host"}),
        "query_strings": "all",
    },
    "Managed-Amplify-ImageOptimization-V2": {
        "id": "766eb028-1aff-4eb2-a5a4-2674e1538f26",
        "ttls": (0, 0, 31536000),
        "cookies": frozenset({"__dpl"}),
        "headers": frozenset(
            {"Authorization", "RSC", "Accept", "CloudFront-Viewer-Country", "X-Amplify-Dpl", "Host"}
        ),
        "query_strings": "all",
    },
}


def _items_or_set(config: dict) -> object:
    """Reduce a CookiesConfig/HeadersConfig/QueryStringsConfig to 'all' or a frozenset of items."""
    behavior = config.get("CookieBehavior") or config.get("HeaderBehavior") or config.get(
        "QueryStringBehavior"
    )
    if behavior == "all":
        return "all"
    items_key = "Cookies" if "Cookies" in config else "Headers" if "Headers" in config else "QueryStrings"
    return frozenset((config.get(items_key) or {}).get("Items", []) or [])


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The managed cache-policy catalog carries a family of Amplify-prefixed entries beyond the base
    Managed-Amplify policy, each with its own fixed TTLs and cache-key settings, consistent across
    List/Get/GetConfig.
    """
    cf = ctx.client("cloudfront")

    marker = None
    managed_by_name = {}
    while True:
        call = {"Type": "managed", "MaxItems": "100"}
        if marker:
            call["Marker"] = marker
        page = cf.list_cache_policies(**call)["CachePolicyList"]
        for item in page.get("Items") or []:
            cfg = item["CachePolicy"]["CachePolicyConfig"]
            managed_by_name[cfg["Name"]] = item["CachePolicy"]["Id"]
        marker = page.get("NextMarker")
        if not marker:
            break

    missing = set(_AMPLIFY_CACHE_POLICIES) - set(managed_by_name)
    assert not missing, f"Amplify-family managed cache policies missing from the catalog: {sorted(missing)}"

    for name, expected in _AMPLIFY_CACHE_POLICIES.items():
        listed_id = managed_by_name[name]
        assert listed_id == expected["id"], (
            f"{name} is listed under id {listed_id!r}, expected {expected['id']!r}"
        )

        got = cf.get_cache_policy(Id=expected["id"])["CachePolicy"]
        assert got["Id"] == expected["id"], got["Id"]
        got_cfg = got["CachePolicyConfig"]
        assert got_cfg["Name"] == name, (
            f"GetCachePolicy({expected['id']}) reported {got_cfg['Name']!r}, List said {name!r}"
        )

        cfg_only = cf.get_cache_policy_config(Id=expected["id"])["CachePolicyConfig"]
        assert cfg_only == got_cfg, f"GetCachePolicyConfig and GetCachePolicy disagree on the body of {name}"

        ttls = (got_cfg["MinTTL"], got_cfg["DefaultTTL"], got_cfg["MaxTTL"])
        assert ttls == expected["ttls"], f"{name}: expected TTLs (min,default,max)={expected['ttls']}, got {ttls}"

        params = got_cfg["ParametersInCacheKeyAndForwardedToOrigin"]
        cookies = _items_or_set(params["CookiesConfig"])
        assert cookies == expected["cookies"], (
            f"{name}: expected cookies-in-cache-key {expected['cookies']!r}, got {cookies!r}"
        )
        headers = _items_or_set(params["HeadersConfig"])
        assert headers == expected["headers"], (
            f"{name}: expected headers-in-cache-key {expected['headers']!r}, got {headers!r}"
        )
        query_strings = _items_or_set(params["QueryStringsConfig"])
        assert query_strings == expected["query_strings"], (
            f"{name}: expected query-strings-in-cache-key {expected['query_strings']!r}, "
            f"got {query_strings!r}"
        )
        assert params["EnableAcceptEncodingGzip"] is True and params["EnableAcceptEncodingBrotli"] is True, (
            f"{name}: every Amplify-family policy enables both Gzip and Brotli in the cache key, "
            f"got Gzip={params['EnableAcceptEncodingGzip']} Brotli={params['EnableAcceptEncodingBrotli']}"
        )

    # The managed partition and the custom partition are disjoint for this family too.
    custom_ids = {
        item["CachePolicy"]["Id"]
        for item in (
            cf.list_cache_policies(Type="custom", MaxItems="100")["CachePolicyList"].get("Items") or []
        )
    }
    amplify_ids = {expected["id"] for expected in _AMPLIFY_CACHE_POLICIES.values()}
    overlap = custom_ids & amplify_ids
    assert not overlap, f"Amplify-family managed cache policies must not appear under Type='custom': {overlap}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
