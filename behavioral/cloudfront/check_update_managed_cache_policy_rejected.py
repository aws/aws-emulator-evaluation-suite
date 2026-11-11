"""update-managed-cache-policy-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-managed-cache-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _force_delete_cache_policy(cf, policy_id):
    resp = cf.get_cache_policy(Id=policy_id)
    cf.delete_cache_policy(Id=policy_id, IfMatch=resp["ETag"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCachePolicy on the managed CachingOptimized policy fails with IllegalUpdate and its exact message and
    leaves its config unchanged, while the same update on a policy the check owns succeeds."""
    cf = ctx.client("cloudfront")

    # Positive control: a custom policy this check owns can be updated.
    name = ctx.unique_name("sim2real-behav-umcp-")
    own = cf.create_cache_policy(
        CachePolicyConfig={
            "Name": name,
            "Comment": "positive control for managed-policy update rejection",
            "DefaultTTL": 100,
            "MaxTTL": 200,
            "MinTTL": 10,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "EnableAcceptEncodingGzip": True,
                "HeadersConfig": {"HeaderBehavior": "none"},
                "CookiesConfig": {"CookieBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
            },
        }
    )["CachePolicy"]
    own_id = own["Id"]
    ctx.on_cleanup(lambda: _force_delete_cache_policy(cf, own_id))

    own_got = cf.get_cache_policy(Id=own_id)
    own_cfg = dict(own_got["CachePolicy"]["CachePolicyConfig"])
    own_cfg["Comment"] = "positive control, updated"
    own_updated = cf.update_cache_policy(
        Id=own_id, IfMatch=own_got["ETag"], CachePolicyConfig=own_cfg
    )
    assert (
        own_updated["CachePolicy"]["CachePolicyConfig"]["Comment"] == "positive control, updated"
    ), "UpdateCachePolicy must succeed on a policy this check owns before the managed-policy rejection means anything"

    current = cf.get_cache_policy(Id=_MANAGED_CACHING_OPTIMIZED)
    etag = current["ETag"]
    managed_config = current["CachePolicy"]["CachePolicyConfig"]

    mutated_config = dict(managed_config)
    mutated_config["Comment"] = "sim2real attempted mutation of a managed policy"

    code, message = _error(
        lambda: cf.update_cache_policy(
            Id=_MANAGED_CACHING_OPTIMIZED, IfMatch=etag, CachePolicyConfig=mutated_config
        )
    )
    assert code == "IllegalUpdate", f"expected IllegalUpdate updating a managed policy, got {code}"
    expected_message = "The request failed because update is not allowed for this policy."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Confirm the managed policy was left untouched.
    after = cf.get_cache_policy(Id=_MANAGED_CACHING_OPTIMIZED)["CachePolicy"]["CachePolicyConfig"]
    assert after == managed_config, f"expected managed policy config unchanged, got {after}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
