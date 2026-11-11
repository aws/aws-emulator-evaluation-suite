"""e2e-pull-through-cache-duplicate-rule-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pull-through-cache-duplicate-rule-rejected"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePullThroughCacheRule on a prefix that has a rule is refused
    PullThroughCacheRuleAlreadyExistsException with the exact message and the rule stays the only
    one; a free prefix is accepted, and once the rule is deleted the identical create succeeds."""
    ecr = ctx.client("ecr")

    prefix_a = ctx.unique_name("sim2real-pta-")
    ecr.create_pull_through_cache_rule(ecrRepositoryPrefix=prefix_a, upstreamRegistryUrl="quay.io")
    ctx.on_cleanup(lambda: _safe_delete(ecr, prefix_a))

    code, message = _error(
        lambda: ecr.create_pull_through_cache_rule(ecrRepositoryPrefix=prefix_a, upstreamRegistryUrl="quay.io")
    )
    assert code == "PullThroughCacheRuleAlreadyExistsException", f"expected AlreadyExists, got {code!r}"
    expected = f"A pull-through cache rule with repository prefix '{prefix_a}' already exists in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    rules_a = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix_a])["pullThroughCacheRules"]
    assert len(rules_a) == 1, f"duplicate create must not add or replace the existing rule: {rules_a!r}"
    assert rules_a[0]["upstreamRegistryUrl"] == "quay.io", f"existing mapping must be untouched: {rules_a[0]!r}"

    prefix_b = ctx.unique_name("sim2real-ptb-")
    ecr.create_pull_through_cache_rule(ecrRepositoryPrefix=prefix_b, upstreamRegistryUrl="quay.io")
    ctx.on_cleanup(lambda: _safe_delete(ecr, prefix_b))

    rules_b = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix_b])["pullThroughCacheRules"]
    assert len(rules_b) == 1, f"a free prefix must still accept a new rule: {rules_b!r}"

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix_a)
    not_found_code, not_found_message = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix_a])
    )
    assert not_found_code == "PullThroughCacheRuleNotFoundException", (
        f"expected NotFound after delete, got {not_found_code!r}"
    )
    expected = f"A pull-through cache rule with repository prefix '{prefix_a}' does not exist in the registry with id '{ctx.account}'"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    ecr.create_pull_through_cache_rule(ecrRepositoryPrefix=prefix_a, upstreamRegistryUrl="quay.io")
    ctx.on_cleanup(lambda: _safe_delete(ecr, prefix_a))

    rules_a_restored = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix_a])[
        "pullThroughCacheRules"
    ]
    assert len(rules_a_restored) == 1, f"identical call must succeed once the block is gone: {rules_a_restored!r}"
    assert rules_a_restored[0]["upstreamRegistryUrl"] == "quay.io", rules_a_restored[0]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(ecr, prefix):
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
