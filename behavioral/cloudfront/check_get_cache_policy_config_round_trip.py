"""get-cache-policy-config-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-cache-policy-config-round-trip"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCachePolicyConfig returns MinTTL, DefaultTTL and MaxTTL exactly as created, with DefaultTTL 2**31
    and MaxTTL 2**31 + 1 so that a 32-bit store would wrap them negative, plus the create's Name and ETag."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cp-")

    min_ttl = 1
    default_ttl = 2147483648  # 2**31
    max_ttl = 2147483649

    created = cf.create_cache_policy(
        CachePolicyConfig={
            "Comment": "sim2real behavioral check cache policy",
            "Name": name,
            "DefaultTTL": default_ttl,
            "MaxTTL": max_ttl,
            "MinTTL": min_ttl,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "EnableAcceptEncodingGzip": True,
                "EnableAcceptEncodingBrotli": False,
                "HeadersConfig": {"HeaderBehavior": "none"},
                "CookiesConfig": {"CookieBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
            },
        }
    )
    policy_id = created["CachePolicy"]["Id"]
    created_etag = created["ETag"]

    def _cleanup():
        etag = cf.get_cache_policy(Id=policy_id)["ETag"]
        cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    fetched = cf.get_cache_policy_config(Id=policy_id)
    config = fetched["CachePolicyConfig"]

    assert config["Name"] == name, f"Name: expected {name!r}, got {config['Name']!r}"
    assert config["DefaultTTL"] == default_ttl, f"DefaultTTL: expected {default_ttl}, got {config['DefaultTTL']}"
    assert config["MaxTTL"] == max_ttl, f"MaxTTL: expected {max_ttl}, got {config['MaxTTL']}"
    assert config["MinTTL"] == min_ttl, f"MinTTL: expected {min_ttl}, got {config['MinTTL']}"
    for field in ("DefaultTTL", "MaxTTL", "MinTTL"):
        assert isinstance(config[field], int) and config[field] >= 0, (
            f"{field}: expected a non-negative int (no 32-bit wraparound), got {config[field]!r}"
        )
    assert fetched["ETag"] == created_etag, f"ETag: expected {created_etag!r}, got {fetched['ETag']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
