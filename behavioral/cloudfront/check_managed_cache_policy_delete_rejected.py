"""managed-cache-policy-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a call AWS refuses is never read as a mere code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "managed-cache-policy-delete-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCachePolicy on an AWS-managed cache policy fails with IllegalDelete (not AccessDenied),
    the policy still exists, and deleting a policy this check owns succeeds.
    """
    cf = ctx.client("cloudfront")

    # Positive control: a target rejecting every DeleteCachePolicy would otherwise pass.
    name = ctx.unique_name("sim2real-cachepolicy-")
    created = cf.create_cache_policy(CachePolicyConfig={
        "Name": name,
        "Comment": "sim2real positive control for managed-policy delete rejection",
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "MinTTL": 1,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })
    policy_id = created["CachePolicy"]["Id"]

    def _cleanup(policy_id=policy_id):
        try:
            fresh = cf.get_cache_policy(Id=policy_id)
            cf.delete_cache_policy(Id=policy_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
                raise

    ctx.on_cleanup(_cleanup)

    cf.delete_cache_policy(Id=policy_id, IfMatch=created["ETag"])
    gone_code, gone_message = _error(lambda: cf.get_cache_policy(Id=policy_id))
    assert gone_code == "NoSuchCachePolicy", (
        f"expected NoSuchCachePolicy reading the just-deleted customer policy, got {gone_code}"
    )
    expected = "The specified cache policy does not exist."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    got = cf.get_cache_policy(Id=MANAGED_CACHING_OPTIMIZED)
    assert got["CachePolicy"]["CachePolicyConfig"]["Name"] == "Managed-CachingOptimized", (
        f"expected Managed-CachingOptimized, got {got['CachePolicy']['CachePolicyConfig']['Name']!r}"
    )
    # GetCachePolicy does not report Type ('managed'|'custom'); only ListCachePolicies does.
    managed_items = cf.list_cache_policies(Type="managed")["CachePolicyList"].get("Items", [])
    assert any(
        item["CachePolicy"]["Id"] == MANAGED_CACHING_OPTIMIZED and item.get("Type") == "managed"
        for item in managed_items
    ), "Managed-CachingOptimized should be listed under Type='managed'"

    code, message = _error(lambda: cf.delete_cache_policy(Id=MANAGED_CACHING_OPTIMIZED, IfMatch=got["ETag"]))
    assert code == "IllegalDelete", f"expected IllegalDelete deleting a managed policy, got {code}"
    expected = "The request failed because delete is not allowed for this policy."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # and it must still be there afterwards
    still = cf.get_cache_policy(Id=MANAGED_CACHING_OPTIMIZED)
    assert still["CachePolicy"]["Id"] == MANAGED_CACHING_OPTIMIZED, (
        f"managed policy {MANAGED_CACHING_OPTIMIZED} should still exist after a rejected delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
