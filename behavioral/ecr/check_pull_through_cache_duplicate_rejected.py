"""pull-through-cache-duplicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "pull-through-cache-duplicate-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a PullThroughCacheRule for a prefix that already has one MUST fail --
    a permissive emulator that allows silently replacing the rule diverges from the
    real uniqueness constraint on ecrRepositoryPrefix."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix = ctx.unique_name("sim2real-behav-ptc-")[:30].rstrip("-")  # ecrRepositoryPrefix <= 30
    ctx.on_cleanup(lambda _p=prefix: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=_p))
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistryUrl="public.ecr.aws"
    )

    # The duplicate attempt targets a DIFFERENT upstream than the original, so a target
    # that rejects the call but silently applies it anyway is still caught below.
    code, message = _error_code(
        lambda: ecr.create_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix, upstreamRegistryUrl="quay.io"
        )
    )
    assert code == "PullThroughCacheRuleAlreadyExistsException", (
        f"expected PullThroughCacheRuleAlreadyExistsException, got {code}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{prefix}' already exists in the "
        f"registry with id '{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Independent read at the destination: exactly one rule for this prefix, and its
    # mapping is the original one -- the rejected duplicate must not have been applied.
    rules = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    assert len(rules) == 1, f"rejected duplicate must not add a second rule: {rules!r}"
    assert rules[0]["upstreamRegistryUrl"] == "public.ecr.aws", (
        f"rejected duplicate must leave the original mapping untouched, got {rules[0]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
