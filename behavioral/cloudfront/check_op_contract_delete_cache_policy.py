"""op-contract-deleteCachePolicy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteCachePolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# Managed-CachingDisabled: a predefined, immutable cache policy present in every account.
_MANAGED_CACHING_DISABLED_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCachePolicy: a customer-owned policy deletes cleanly, but attempting to
    delete an AWS managed cache policy is rejected with IllegalDelete."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cachepolicy-")

    created = cf.create_cache_policy(
        CachePolicyConfig={
            "Name": name,
            "Comment": "sim2real behavioral check",
            "DefaultTTL": 86400,
            "MaxTTL": 31536000,
            "MinTTL": 1,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "EnableAcceptEncodingGzip": False,
                "HeadersConfig": {"HeaderBehavior": "none"},
                "CookiesConfig": {"CookieBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
            },
        }
    )
    policy_id = created["CachePolicy"]["Id"]
    etag = created["ETag"]

    def _cleanup(policy_id=policy_id):
        try:
            fresh = cf.get_cache_policy(Id=policy_id)
            cf.delete_cache_policy(Id=policy_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: a managed policy is immutable and can't be deleted
    managed = cf.get_cache_policy(Id=_MANAGED_CACHING_DISABLED_ID)
    illegal_code, illegal_message = _error(
        lambda: cf.delete_cache_policy(Id=_MANAGED_CACHING_DISABLED_ID, IfMatch=managed["ETag"])
    )
    assert illegal_code == "IllegalDelete", f"expected IllegalDelete, got {illegal_code}"
    assert illegal_message == "The request failed because delete is not allowed for this policy.", (
        f"expected the exact refusal message, got {illegal_message!r}"
    )

    # effect-absent: the rejected delete must not have touched the managed policy
    still_managed = cf.get_cache_policy(Id=_MANAGED_CACHING_DISABLED_ID)
    assert still_managed["CachePolicy"]["Id"] == _MANAGED_CACHING_DISABLED_ID, (
        f"managed policy {_MANAGED_CACHING_DISABLED_ID} should survive a rejected delete, "
        f"got {still_managed['CachePolicy']['Id']}"
    )

    # success path: our own policy deletes cleanly
    cf.delete_cache_policy(Id=policy_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_cache_policy(Id=policy_id))
    assert gone_code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy, got {gone_code}"
    assert gone_message == "The specified cache policy does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation on the now-dead id also fails, with the same specific not-found code
    dead_mutation_code, dead_mutation_message = _error(
        lambda: cf.delete_cache_policy(Id=policy_id, IfMatch=etag)
    )
    assert dead_mutation_code == "NoSuchCachePolicy", (
        f"expected NoSuchCachePolicy deleting an already-deleted policy, got {dead_mutation_code}"
    )
    assert dead_mutation_message == "The specified cache policy does not exist.", (
        f"expected the exact refusal message, got {dead_mutation_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
