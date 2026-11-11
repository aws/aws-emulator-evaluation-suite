"""create-pull-through-cache-rule-duplicate-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-pull-through-cache-rule-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePullThroughCacheRule for a prefix that already has a rule is rejected with
    PullThroughCacheRuleAlreadyExistsException rather than silently overwriting the
    existing upstream mapping."""
    ecr = ctx.client("ecr")
    prefix = _ecr_name(ctx, "sim2realptc")

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="ecr-public",
        upstreamRegistryUrl="public.ecr.aws",
    )
    ctx.on_cleanup(lambda: _safe_delete_rule(ecr, prefix))

    rules = {r["ecrRepositoryPrefix"]: r for r in ecr.describe_pull_through_cache_rules()["pullThroughCacheRules"]}
    assert prefix in rules, f"expected {prefix!r} among {sorted(rules)}"
    assert rules[prefix]["upstreamRegistryUrl"] == "public.ecr.aws", (
        f"expected public.ecr.aws, got {rules[prefix]['upstreamRegistryUrl']!r}"
    )

    # Attempting to create a second rule for the SAME prefix pointing at a different
    # upstream registry must be rejected, not silently applied. Use "quay" (a public
    # upstream that needs no credentialArn) rather than "docker-hub": Docker Hub now
    # requires a credentialArn on CreatePullThroughCacheRule, which would fail with a
    # ValidationException before the duplicate-prefix check is ever reached, masking the
    # behavior this check is actually about.
    err, message = _error(
        lambda: ecr.create_pull_through_cache_rule(
            ecrRepositoryPrefix=prefix,
            upstreamRegistry="quay",
            upstreamRegistryUrl="quay.io",
        )
    )
    assert err == "PullThroughCacheRuleAlreadyExistsException", f"expected AlreadyExists, got {err}"
    expected = (
        f"A pull-through cache rule with repository prefix '{prefix}' already exists in the "
        f"registry with id '{ctx.account}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The original rule's mapping must be untouched by the rejected attempt.
    rules_after = {
        r["ecrRepositoryPrefix"]: r for r in ecr.describe_pull_through_cache_rules()["pullThroughCacheRules"]
    }
    assert rules_after[prefix]["upstreamRegistryUrl"] == "public.ecr.aws", (
        f"rejected duplicate mutated the mapping: expected public.ecr.aws, "
        f"got {rules_after[prefix]['upstreamRegistryUrl']!r}"
    )

    # Restore: the rejection is specific to the prefix already being mapped, not to the
    # quay upstream itself. Remove the blocking rule, confirm it is actually gone via an
    # independent read, then replay the identical call that was rejected above and demand
    # it now succeeds.
    ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    rules_deleted = {
        r["ecrRepositoryPrefix"]: r for r in ecr.describe_pull_through_cache_rules()["pullThroughCacheRules"]
    }
    assert prefix not in rules_deleted, f"expected {prefix!r} gone after delete, still present: {rules_deleted.get(prefix)}"

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="quay",
        upstreamRegistryUrl="quay.io",
    )
    rules_restored = {
        r["ecrRepositoryPrefix"]: r for r in ecr.describe_pull_through_cache_rules()["pullThroughCacheRules"]
    }
    assert prefix in rules_restored and rules_restored[prefix]["upstreamRegistryUrl"] == "quay.io", (
        f"expected the identical create to succeed once the blocking rule was removed, "
        f"got {rules_restored.get(prefix)}"
    )


def _ecr_name(ctx, base: str, max_len: int = 30) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9\-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw[:max_len]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_rule(ecr, prefix):
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
