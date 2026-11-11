"""op-contract-deletePullThroughCacheRule."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deletePullThroughCacheRule"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePullThroughCacheRule returns the rule's prefix and upstream URL and the rule leaves
    the listing; an unknown prefix is refused PullThroughCacheRuleNotFoundException with the
    exact message, and the prefix can be used again."""
    ecr = ctx.client("ecr")
    prefix = ctx.unique_name("sim2real-ecr-ptc-")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)

    ctx.on_cleanup(_cleanup)

    resp = ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    cleaned["done"] = True
    assert resp["ecrRepositoryPrefix"] == prefix, (
        f"delete response echoed ecrRepositoryPrefix {resp['ecrRepositoryPrefix']!r}, expected {prefix!r}"
    )
    assert resp["upstreamRegistryUrl"] == "public.ecr.aws", (
        f"delete response echoed upstreamRegistryUrl {resp['upstreamRegistryUrl']!r}, expected "
        f"'public.ecr.aws'"
    )

    described = ecr.describe_pull_through_cache_rules()["pullThroughCacheRules"]
    assert all(r["ecrRepositoryPrefix"] != prefix for r in described), (
        f"deleted prefix {prefix!r} is still listed by DescribePullThroughCacheRules: {described!r}"
    )

    code, message = _error(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix))
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"deleting the already-deleted prefix {prefix!r} raised {code!r}, expected "
        f"'PullThroughCacheRuleNotFoundException'"
    )
    expected = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist in the "
        f"registry with id '{ctx.account}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The freed prefix must be reusable, not left in some half-deleted reserved state.
    cleaned["done"] = False
    recreate_resp = ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )
    assert recreate_resp["ecrRepositoryPrefix"] == prefix, (
        f"recreating the freed prefix echoed {recreate_resp['ecrRepositoryPrefix']!r}, expected {prefix!r}"
    )
    recreated = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    assert len(recreated) == 1 and recreated[0]["ecrRepositoryPrefix"] == prefix, (
        f"the recreated prefix {prefix!r} is not visible via DescribePullThroughCacheRules: {recreated!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error (code, message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
