"""validate-pull-through-cache-rule-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-pull-through-cache-rule-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Validating a pull-through cache rule that was never created returns
    PullThroughCacheRuleNotFoundException, while validating a real rule created in the
    same file succeeds without raising (control)."""
    ecr = ctx.client("ecr")

    never_created_prefix = "s2r" + uuid.uuid4().hex[:10]

    # negative
    code, message = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=never_created_prefix)
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException for a never-created prefix, got {code!r}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{never_created_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # positive control: a real rule validates without raising PullThroughCacheRuleNotFoundException
    real_prefix = "s2r" + uuid.uuid4().hex[:10]
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=real_prefix,
        upstreamRegistryUrl="public.ecr.aws",
        upstreamRegistry="ecr-public",
    )

    def _cleanup():
        try:
            ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
        except ClientError as e:
            if e.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    validate_resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    assert validate_resp["ecrRepositoryPrefix"] == real_prefix, (
        f"expected ecrRepositoryPrefix={real_prefix!r}, got {validate_resp.get('ecrRepositoryPrefix')!r}"
    )
    assert validate_resp["isValid"] is True, (
        f"expected isValid=True for a real rule against a public, credential-free upstream, "
        f"got {validate_resp!r}"
    )

    # after deleting the real rule, validation reverts to not-found too
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    code_after_delete, message_after_delete = _error(
        lambda: ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=real_prefix)
    )
    assert code_after_delete == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException after deleting the rule, got {code_after_delete!r}"
    )
    expected_message_after_delete = (
        f"A pull-through cache rule with repository prefix '{real_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message_after_delete == expected_message_after_delete, (
        f"expected the exact refusal message {expected_message_after_delete!r}, got {message_after_delete!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call with PullThroughCacheRuleNotFoundException, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
