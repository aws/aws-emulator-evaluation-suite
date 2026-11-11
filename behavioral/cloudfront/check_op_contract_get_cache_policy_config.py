"""op-contract-get-cache-policy-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-cache-policy-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCachePolicyConfig returns the exact config written on create, and 404s on unknown Id."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cp-")
    config = {
        "Comment": "sim2real behavioral test cache policy",
        "Name": name,
        "DefaultTTL": 50,
        "MaxTTL": 100,
        "MinTTL": 1,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }
    created = cf.create_cache_policy(CachePolicyConfig=config)
    policy_id = created["CachePolicy"]["Id"]
    etag = created["ETag"]

    def _cleanup() -> None:
        try:
            cur = cf.get_cache_policy(Id=policy_id)
            cf.delete_cache_policy(Id=policy_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract
    got = cf.get_cache_policy_config(Id=policy_id)
    cfg = got["CachePolicyConfig"]
    assert cfg["Name"] == name, f"Name: expected {name!r}, got {cfg['Name']!r}"
    assert cfg["MinTTL"] == 1, f"MinTTL: expected 1, got {cfg['MinTTL']!r}"
    assert cfg["MaxTTL"] == 100, f"MaxTTL: expected 100, got {cfg['MaxTTL']!r}"
    assert got["ETag"] == etag, f"ETag: expected {etag!r}, got {got['ETag']!r}"

    # distinct error boundary: unknown Id
    code, message = _error(lambda: cf.get_cache_policy_config(Id="ffffffff-ffff-ffff-ffff-ffffffffffff"))
    assert code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy, got {code}"
    not_found_message = "The specified cache policy does not exist."
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
