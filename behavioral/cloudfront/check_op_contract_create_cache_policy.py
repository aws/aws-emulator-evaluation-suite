"""op-contract-create-cache-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-cache-policy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCachePolicy: round-trips the submitted config (TTLs, name) and rejects a
    duplicate Name with CachePolicyAlreadyExists."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-cachepolicy-")
    policy_config = _policy_config(name)

    resp = cf.create_cache_policy(CachePolicyConfig=policy_config)
    policy_id = resp["CachePolicy"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_cache_policy(Id=policy_id, IfMatch=etag))

    # Independent read: GetCachePolicyConfig, not the create response's own echo.
    fetched_config = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert fetched_config["Name"] == name, f"expected Name {name!r}, got {fetched_config['Name']!r}"
    assert fetched_config["MinTTL"] == 1, f"expected MinTTL 1, got {fetched_config['MinTTL']}"
    assert fetched_config["MaxTTL"] == 31536000, f"expected MaxTTL 31536000, got {fetched_config['MaxTTL']}"
    assert fetched_config["DefaultTTL"] == 86400, f"expected DefaultTTL 86400, got {fetched_config['DefaultTTL']}"

    # Error boundary: duplicate Name is rejected.
    code, message = _error(lambda: cf.create_cache_policy(CachePolicyConfig=_policy_config(name)))
    assert code == "CachePolicyAlreadyExists", f"expected CachePolicyAlreadyExists, got {code}"
    expected = "Another cache policy with the same name already exists within the aws account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent, via an independent read: exactly one policy exists under that Name, the original.
    listed = cf.list_cache_policies(Type="custom")
    matching = [
        item
        for item in listed.get("CachePolicyList", {}).get("Items", [])
        if item["CachePolicy"]["CachePolicyConfig"]["Name"] == name
    ]
    assert len(matching) == 1, f"expected exactly 1 policy named {name!r}, found {len(matching)}"
    assert matching[0]["CachePolicy"]["Id"] == policy_id


def _policy_config(name):
    return {
        "Name": name,
        "MinTTL": 1,
        "MaxTTL": 31536000,
        "DefaultTTL": 86400,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
