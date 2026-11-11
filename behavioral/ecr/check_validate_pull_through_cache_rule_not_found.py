"""validate-pull-through-cache-rule-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-pull-through-cache-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidatePullThroughCacheRule on an unregistered prefix is refused
    PullThroughCacheRuleNotFoundException with the exact message, a registered rule returns
    isValid true with no failure, and once deleted it is refused the same way."""
    ecr = ctx.client("ecr")

    unregistered_prefix = _ptc_prefix(ctx, "ptcmissv")
    code, message = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=unregistered_prefix)
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException for an unregistered prefix, got {code!r}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{unregistered_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # positive control: a registered rule validates without raising
    registered_prefix = _ptc_prefix(ctx, "ptcpresv")
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=registered_prefix,
        upstreamRegistryUrl="quay.io",
        upstreamRegistry="quay",
    )
    ctx.on_cleanup(
        lambda: _safe_delete_ptcr(ecr, registered_prefix)
    )

    validate_resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=registered_prefix)
    assert validate_resp["ecrRepositoryPrefix"] == registered_prefix, (
        f"expected ecrRepositoryPrefix={registered_prefix!r}, got {validate_resp['ecrRepositoryPrefix']!r}"
    )
    assert validate_resp["isValid"] is True, (
        f"expected isValid=True for a registered rule with a reachable public upstream, "
        f"got {validate_resp['isValid']!r}"
    )
    assert not validate_resp.get("failure"), (
        f"expected no failure reason for a valid rule, got {validate_resp.get('failure')!r}"
    )

    # the delete is already happening via ctx.on_cleanup; assert it here too so the
    # teardown becomes a free negative instead of an unasserted side effect
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=registered_prefix)
    code_after_delete, message_after_delete = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=registered_prefix)
    )
    assert code_after_delete == "PullThroughCacheRuleNotFoundException", (
        f"expected validation to revert to PullThroughCacheRuleNotFoundException after delete, "
        f"got {code_after_delete!r}"
    )
    expected_message_after_delete = (
        f"A pull-through cache rule with repository prefix '{registered_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message_after_delete == expected_message_after_delete, (
        f"expected the exact refusal message {expected_message_after_delete!r}, got {message_after_delete!r}"
    )


def _ptc_prefix(ctx, tag: str) -> str:
    """Build an ecrRepositoryPrefix (pattern: lowercase alnum, max 30 chars) from
    ctx.unique_name by stripping the separators unique_name adds."""
    raw = ctx.unique_name(f"sim2real{tag}").lower()
    alnum = "".join(ch for ch in raw if ch.isalnum())
    return alnum[:30]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
