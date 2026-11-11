"""pull-through-cache-rule-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "pull-through-cache-rule-lifecycle"
GROUP = 'pull-through-cache'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePullThroughCacheRule -> visible in DescribePullThroughCacheRules ->
    DeletePullThroughCacheRule removes it."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix = ctx.unique_name("sim2real-behav-ptc-")[:30].rstrip("-")  # ecrRepositoryPrefix <= 30
    def _cleanup():
        try:
            ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PullThroughCacheRuleNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )

    rules = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    assert len(rules) == 1, f"expected exactly 1 rule for prefix {prefix!r}, got {rules!r}"
    assert rules[0]["ecrRepositoryPrefix"] == prefix, (
        f"expected ecrRepositoryPrefix {prefix!r}, got {rules[0]['ecrRepositoryPrefix']!r}"
    )

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)

    code, message = _error_code(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException, got {code}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' does not exist in the "
        f"registry with id '{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
