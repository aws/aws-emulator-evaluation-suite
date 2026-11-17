"""describe-pull-through-cache-rules-unissued-token-rejected-during-pagination."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-pull-through-cache-rules-unissued-token-rejected-during-pagination"
GROUP = "pull-through-cache"
SERVICES = ["ecr"]

_INVALID_NEXT_TOKEN = (
    "InvalidParameterException",
    "Invalid parameter at 'NextToken' failed to satisfy constraint: 'Invalid next token provided'",
)


def expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        actual = (err.get("Code"), err.get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags(
    "axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control"
)
def run(ctx) -> None:
    """DescribePullThroughCacheRules pages a real, previously-issued nextToken from one created
    rule to the next, but refuses a token no earlier page issued with the exact
    InvalidParameterException message, and the same real token keeps paging afterwards.
    """
    ecr = ctx.client("ecr")
    prefix_a = _prefix_name(ctx, "ptc-u-a")
    prefix_b = _prefix_name(ctx, "ptc-u-b")

    ecr.create_pull_through_cache_rule(ecrRepositoryPrefix=prefix_a, upstreamRegistryUrl="quay.io")
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, prefix_a))
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix_b, upstreamRegistryUrl="registry.k8s.io"
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, prefix_b))

    target = {prefix_a: "quay.io", prefix_b: "registry.k8s.io"}
    found: dict[str, str] = {}
    a_real_token = None
    next_token = None
    for _ in range(50):
        page = ecr.describe_pull_through_cache_rules(
            **({"maxResults": 1, "nextToken": next_token} if next_token else {"maxResults": 1})
        )
        rules = page["pullThroughCacheRules"]
        assert len(rules) <= 1, f"expected MaxResults=1 to return at most 1 rule, got {rules!r}"
        for r in rules:
            if r["ecrRepositoryPrefix"] in target:
                found[r["ecrRepositoryPrefix"]] = r["upstreamRegistryUrl"]
        next_token = page.get("nextToken")
        if next_token and a_real_token is None:
            a_real_token = next_token
        if set(target) <= set(found) or not next_token:
            break
    else:
        raise AssertionError("pagination did not surface both created rules within 50 pages")

    assert set(target) <= set(found), (
        f"expected pagination with MaxResults=1 to surface both {sorted(target)}, found {sorted(found)}"
    )
    for repo_prefix, upstream in target.items():
        assert found[repo_prefix] == upstream, (
            f"expected {repo_prefix!r} to report upstreamRegistryUrl {upstream!r}, got "
            f"{found[repo_prefix]!r}"
        )
    assert a_real_token, "expected pagination to have issued at least one real nextToken"

    # A token no earlier page issued is refused -- even though the rules it would have paged
    # through are still there and still readable.
    expect_error(
        lambda: ecr.describe_pull_through_cache_rules(nextToken="sim2real-not-a-real-token"),
        *_INVALID_NEXT_TOKEN,
    )

    # Positive control: the SAME real token a page actually issued above still pages correctly
    # after the refusal, proving the rejection is about the token's provenance, not its shape,
    # not the account, and not these rules.
    replay = ecr.describe_pull_through_cache_rules(maxResults=1, nextToken=a_real_token)
    replayed_rules = replay["pullThroughCacheRules"]
    assert len(replayed_rules) <= 1, (
        f"expected MaxResults=1 to still return at most 1 rule replaying a real token, got "
        f"{replayed_rules!r}"
    )
    assert replayed_rules, "expected replaying a real, previously-issued token to still return a rule"
    assert replayed_rules[0]["ecrRepositoryPrefix"] in target, (
        f"expected the replayed page to return one of this check's own rules, got "
        f"{replayed_rules[0]['ecrRepositoryPrefix']!r}"
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
