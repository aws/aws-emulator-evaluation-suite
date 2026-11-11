"""pull-through-cache-rule-create-defaults-and-describe-pagination."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "pull-through-cache-rule-create-defaults-and-describe-pagination"
GROUP = "pull-through-cache"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/DescribePullThroughCacheRules never echo upstreamRegistry, and report
    upstreamRepositoryPrefix only when supplied; Describe pages with maxResults=1 across both
    rules and filters by ecrRepositoryPrefixes.
    """
    ecr = ctx.client("ecr")
    first_prefix = _prefix_name(ctx, "ptc-a")
    second_prefix = _prefix_name(ctx, "ptc-b")

    # registry-1.docker.io requires a credentialArn; registry.k8s.io and quay.io allow anonymous rules.
    created = ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=first_prefix, upstreamRegistryUrl="registry.k8s.io"
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, first_prefix))
    assert created["ecrRepositoryPrefix"] == first_prefix, (
        f"expected ecrRepositoryPrefix {first_prefix!r} echoed back, "
        f"got {created['ecrRepositoryPrefix']!r}"
    )
    assert "upstreamRegistry" not in created, (
        f"expected no upstreamRegistry key on Create when none was given, got {created!r}"
    )
    assert "upstreamRepositoryPrefix" not in created, (
        "expected upstreamRepositoryPrefix to be ABSENT (the ROOT default is not reported) on Create when "
        f"omitted, got {created!r}"
    )
    assert created.get("createdAt") is not None, "expected a createdAt timestamp on create"

    # Even an explicitly supplied upstreamRegistry is never echoed on Create or Describe.
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=second_prefix,
        upstreamRegistry="quay",
        upstreamRegistryUrl="quay.io",
        upstreamRepositoryPrefix="ROOT",
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, second_prefix))

    # AWS rejects maxResults combined with ecrRepositoryPrefixes ("Cannot provide MaxResults if
    # providing RepositoryPrefixes"), so pagination walks the unfiltered account-wide collection,
    # which may hold other rules; only this check's two rules are asserted, never a total count.
    seen: dict[str, dict] = {}
    next_token = None
    for _ in range(500):
        page = ecr.describe_pull_through_cache_rules(
            **({"maxResults": 1, "nextToken": next_token} if next_token else {"maxResults": 1})
        )
        rules = page["pullThroughCacheRules"]
        next_token = page.get("nextToken")
        if not rules:
            assert not next_token, f"expected no nextToken on an empty page, got {page!r}"
            break
        assert len(rules) == 1, f"expected MaxResults=1 to return at most 1 rule, got {rules!r}"
        seen[rules[0]["ecrRepositoryPrefix"]] = rules[0]
        if not next_token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")

    by_prefix = seen
    assert {first_prefix, second_prefix} <= set(by_prefix), (
        f"expected pagination to eventually surface both {first_prefix!r} and {second_prefix!r}, "
        f"got {set(by_prefix)!r}"
    )
    assert "upstreamRegistry" not in by_prefix[second_prefix], (
        "expected Describe to still omit upstreamRegistry for the rule that explicitly supplied "
        f"it on Create, got {by_prefix[second_prefix]!r}"
    )
    assert by_prefix[second_prefix].get("upstreamRepositoryPrefix") == "ROOT", (
        "expected Describe to report the EXPLICITLY supplied upstreamRepositoryPrefix='ROOT', "
        f"got {by_prefix[second_prefix].get('upstreamRepositoryPrefix')!r}"
    )
    assert "upstreamRepositoryPrefix" not in by_prefix[first_prefix], (
        "expected Describe to still have no upstreamRepositoryPrefix for the rule that never "
        f"supplied one, got {by_prefix[first_prefix]!r}"
    )

    filtered = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[first_prefix])
    filtered_prefixes = {r["ecrRepositoryPrefix"] for r in filtered["pullThroughCacheRules"]}
    assert filtered_prefixes == {first_prefix}, (
        f"expected filtering by ecrRepositoryPrefixes=[{first_prefix!r}] to return exactly that "
        f"rule, got {filtered_prefixes!r}"
    )


def _prefix_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real-behav-{kind}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return raw[:28] if raw else f"sim2real-behav-{kind}"


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
