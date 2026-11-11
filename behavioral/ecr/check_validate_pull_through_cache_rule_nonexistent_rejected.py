"""validate-pull-through-cache-rule-nonexistent-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "validate-pull-through-cache-rule-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidatePullThroughCacheRule on a prefix with no rule is refused
    PullThroughCacheRuleNotFoundException with the exact message, while a registered rule
    validates and is refused the same way once deleted."""
    ecr = ctx.client("ecr")
    real_prefix = _prefix_name(ctx, "real")
    missing_prefix = _prefix_name(ctx, "missing")

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=real_prefix, upstreamRegistry="quay", upstreamRegistryUrl="quay.io"
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, real_prefix))

    ok_resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    assert ok_resp["isValid"] is True, ok_resp

    code, message = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=missing_prefix)
    )
    assert code == "PullThroughCacheRuleNotFoundException", code
    expected_message = (
        f"A pull-through cache rule with repository prefix '{missing_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    code_after_delete, message_after_delete = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    )
    assert code_after_delete == "PullThroughCacheRuleNotFoundException", code_after_delete
    expected_message_after_delete = (
        f"A pull-through cache rule with repository prefix '{real_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message_after_delete == expected_message_after_delete, (
        f"expected the exact refusal message {expected_message_after_delete!r}, got {message_after_delete!r}"
    )


def _prefix_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real{kind}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return raw[:28] if raw else f"sim2real{kind}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
