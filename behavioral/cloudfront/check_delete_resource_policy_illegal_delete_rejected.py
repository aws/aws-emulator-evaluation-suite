"""delete-resource-policy-illegal-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-illegal-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

# CloudFront's managed "CachingOptimized" cache policy. AWS-managed policies can
# never be deleted by any caller, in any account.
_MANAGED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an AWS-managed cache policy is rejected with IllegalDelete; a custom, unattached one deletes fine."""
    cf = ctx.client("cloudfront")

    managed = cf.get_cache_policy(Id=_MANAGED_CACHE_POLICY_ID)
    managed_etag = managed["ETag"]

    code, _ = _error_code(
        lambda: cf.delete_cache_policy(Id=_MANAGED_CACHE_POLICY_ID, IfMatch=managed_etag)
    )
    assert code == "IllegalDelete", f"expected IllegalDelete, got {code!r}"

    # Effect absent: the managed policy is still there and unchanged afterwards.
    still_there = cf.get_cache_policy(Id=_MANAGED_CACHE_POLICY_ID)
    assert still_there["CachePolicy"]["Id"] == _MANAGED_CACHE_POLICY_ID, (
        f"expected {_MANAGED_CACHE_POLICY_ID!r} to still be gettable, got id "
        f"{still_there['CachePolicy']['Id']!r}"
    )
    got_name = still_there["CachePolicy"]["CachePolicyConfig"]["Name"]
    want_name = managed["CachePolicy"]["CachePolicyConfig"]["Name"]
    assert got_name == want_name, f"expected unchanged name {want_name!r}, got {got_name!r}"

    # Positive control in the same file: a custom, unattached cache policy of
    # our own CAN be deleted -- this is not a blanket "delete always rejected".
    name = ctx.unique_name("sim2real-cf-cachepolicy-")
    created = cf.create_cache_policy(
        CachePolicyConfig={
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
    )
    custom_id = created["CachePolicy"]["Id"]
    custom_etag = created["ETag"]
    cleanup_done = {"done": False}

    def _cleanup():
        if cleanup_done["done"]:
            return
        try:
            cf.delete_cache_policy(Id=custom_id, IfMatch=cf.get_cache_policy(Id=custom_id)["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
                raise

    ctx.on_cleanup(_cleanup)

    cf.delete_cache_policy(Id=custom_id, IfMatch=custom_etag)
    cleanup_done["done"] = True

    not_found_code, not_found_message = _error_code(lambda: cf.get_cache_policy(Id=custom_id))
    assert not_found_code == "NoSuchCachePolicy", (
        f"expected the custom policy to be gone (NoSuchCachePolicy), got {not_found_code!r}"
    )
    assert not_found_message == "The specified cache policy does not exist.", (
        f"expected the exact NoSuchCachePolicy message AWS returns, got {not_found_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
