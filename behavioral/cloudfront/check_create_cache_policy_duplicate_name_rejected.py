"""create_cache_policy_duplicate_name_rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create_cache_policy_duplicate_name_rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCachePolicy with a taken Name fails with CachePolicyAlreadyExists and its exact
    message, leaving the original as the only policy of that name; once the original is deleted,
    the same call creates a new policy under the Name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-dupcp-")

    def _config(comment: str) -> dict:
        return {
            "Comment": comment,
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

    # positive control: creating under a fresh name works at all
    first = cf.create_cache_policy(CachePolicyConfig=_config("first"))
    policy_id = first["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _cleanup(ctx, policy_id))

    # a second policy with the same Name (different CallerReference-equivalent identity) must be rejected
    code, msg = _error(lambda: cf.create_cache_policy(CachePolicyConfig=_config("second-duplicate-attempt")))
    assert code == "CachePolicyAlreadyExists", f"expected CachePolicyAlreadyExists, got {code}"
    dup_msg = "Another cache policy with the same name already exists within the aws account."
    assert msg == dup_msg, f"expected message {dup_msg!r}, got {msg!r}"

    # only the original policy exists under that name
    listed = cf.list_cache_policies(Type="custom")
    matching = [
        item
        for item in listed.get("CachePolicyList", {}).get("Items", [])
        if item["CachePolicy"]["CachePolicyConfig"]["Name"] == name
    ]
    assert len(matching) == 1, f"expected exactly 1 policy named {name}, got {len(matching)}"
    assert matching[0]["CachePolicy"]["Id"] == policy_id

    # restore: remove the original, which was the actual source of the conflict
    etag = cf.get_cache_policy(Id=policy_id)["ETag"]
    cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

    # independent read confirms it is gone
    gone_code, gone_msg = _error(lambda: cf.get_cache_policy(Id=policy_id))
    assert gone_code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy after delete, got {gone_code}"
    no_such_msg = "The specified cache policy does not exist."
    assert gone_msg == no_such_msg, f"expected message {no_such_msg!r}, got {gone_msg!r}"

    # a mutation on the dead id also fails, not just a read
    dead_mutation_code, dead_mutation_msg = _error(lambda: cf.delete_cache_policy(Id=policy_id, IfMatch=etag))
    assert dead_mutation_code == "NoSuchCachePolicy", (
        f"expected NoSuchCachePolicy deleting an already-deleted policy, got {dead_mutation_code}"
    )
    assert dead_mutation_msg == no_such_msg, (
        f"expected message {no_such_msg!r}, got {dead_mutation_msg!r}"
    )

    # the identical call that was rejected above must now succeed: the Name was never
    # unusable, only unavailable while the original held it
    second = cf.create_cache_policy(CachePolicyConfig=_config("recreated-after-delete"))
    second_id = second["CachePolicy"]["Id"]
    assert second_id != policy_id
    ctx.on_cleanup(lambda: _cleanup(ctx, second_id))

    # terminal independent read: exactly one policy under the name again, and it is the new one
    relisted = cf.list_cache_policies(Type="custom")
    rematching = [
        item
        for item in relisted.get("CachePolicyList", {}).get("Items", [])
        if item["CachePolicy"]["CachePolicyConfig"]["Name"] == name
    ]
    assert len(rematching) == 1, f"expected exactly 1 policy named {name} after recreate, got {len(rematching)}"
    assert rematching[0]["CachePolicy"]["Id"] == second_id


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _cleanup(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cur = cf.get_cache_policy(Id=policy_id)
        cf.delete_cache_policy(Id=policy_id, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
