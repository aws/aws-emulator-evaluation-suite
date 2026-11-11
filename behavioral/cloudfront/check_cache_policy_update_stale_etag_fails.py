"""cache-policy-update-stale-etag-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    etag = cf.get_cache_policy(Id=policy_id)["ETag"]
    cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

CHECK = "cache-policy-update-stale-etag-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCachePolicy with a superseded (well-formed) IfMatch fails with PreconditionFailed and
    its exact message, and the policy keeps the comment of the update that superseded it."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-cp-stale-")
    create_resp = cf.create_cache_policy(CachePolicyConfig=_minimal_cache_policy_config(name))
    policy_id = create_resp["CachePolicy"]["Id"]
    stale_etag = create_resp["ETag"]
    ctx.on_cleanup(lambda: _delete_cache_policy(cf, policy_id))

    # Advance the ETag once with a real update so `stale_etag` is genuinely
    # superseded (not just malformed).
    cf.update_cache_policy(
        Id=policy_id,
        IfMatch=stale_etag,
        CachePolicyConfig=_minimal_cache_policy_config(name, Comment="v2"),
    )

    code, msg = _error(
        lambda: cf.update_cache_policy(
            Id=policy_id,
            IfMatch=stale_etag,
            CachePolicyConfig=_minimal_cache_policy_config(name, Comment="v3-should-not-apply"),
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    expected_msg = "The request failed because it didn't meet the preconditions for this operation."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The rejected update must not have applied.
    still = cf.get_cache_policy(Id=policy_id)
    assert still["CachePolicy"]["CachePolicyConfig"]["Comment"] == "v2"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
