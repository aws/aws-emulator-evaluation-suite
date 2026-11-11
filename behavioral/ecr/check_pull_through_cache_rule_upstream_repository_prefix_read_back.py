"""pull-through-cache-rule-upstream-repository-prefix-read-back."""

from __future__ import annotations

import datetime
import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pull-through-cache-rule-upstream-repository-prefix-read-back"
GROUP = "representation"
SERVICES = ["ecr"]

_UPSTREAM = "public.ecr.aws"


def _prefix_name(ctx, kind: str) -> str:
    """A unique ecrRepositoryPrefix within the 30-character limit."""
    return re.sub(r"[^a-z0-9-]", "-", ctx.unique_name(f"sim2real-{kind}-").lower())


def _error(fn) -> tuple[str, str]:
    """Run fn and return the AWS error code and message it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected this call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _delete_rule(ecr, prefix: str) -> None:
    """Teardown: the check deletes one rule itself, so not-found is the clean outcome."""
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PullThroughCacheRuleNotFoundException":
            raise


def _fields(rule: dict) -> dict:
    """A rule without its ResponseMetadata and its generated createdAt timestamp."""
    assert isinstance(rule.get("createdAt"), datetime.datetime), (
        f"expected a createdAt timestamp on the rule, got {rule!r}"
    )
    return {k: v for k, v in rule.items() if k not in ("ResponseMetadata", "createdAt")}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreatePullThroughCacheRule and DescribePullThroughCacheRules echo a supplied
    upstreamRepositoryPrefix (ROOT or a named one); a duplicate ecrRepositoryPrefix is refused and
    leaves the rule unchanged, and both Describe and Update of a deleted rule's prefix are not found.

    Reference: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreatePullThroughCacheRule.html"""
    ecr = ctx.client("ecr")
    root_prefix = _prefix_name(ctx, "root")
    named_prefix = _prefix_name(ctx, "named")

    created_root = ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=root_prefix,
        upstreamRegistryUrl=_UPSTREAM,
        upstreamRepositoryPrefix="ROOT",
    )
    ctx.on_cleanup(lambda: _delete_rule(ecr, root_prefix))
    expected_root = {
        "ecrRepositoryPrefix": root_prefix,
        "registryId": ctx.account,
        "upstreamRegistryUrl": _UPSTREAM,
        "upstreamRepositoryPrefix": "ROOT",
    }
    assert _fields(created_root) == expected_root, (
        f"expected CreatePullThroughCacheRule to return {expected_root!r}, got {created_root!r}"
    )

    created_named = ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=named_prefix,
        upstreamRegistryUrl=_UPSTREAM,
        upstreamRepositoryPrefix="docker",
    )
    ctx.on_cleanup(lambda: _delete_rule(ecr, named_prefix))
    expected_named = {
        "ecrRepositoryPrefix": named_prefix,
        "registryId": ctx.account,
        "upstreamRegistryUrl": _UPSTREAM,
        "upstreamRepositoryPrefix": "docker",
    }
    assert _fields(created_named) == expected_named, (
        f"expected CreatePullThroughCacheRule to return {expected_named!r}, got {created_named!r}"
    )

    described = {
        r["ecrRepositoryPrefix"]: _fields(r)
        for r in ecr.describe_pull_through_cache_rules(
            ecrRepositoryPrefixes=[root_prefix, named_prefix]
        )["pullThroughCacheRules"]
    }
    assert described == {root_prefix: expected_root, named_prefix: expected_named}, (
        f"expected DescribePullThroughCacheRules to return both rules as created, got {described!r}"
    )

    duplicate = _error(
        lambda: ecr.create_pull_through_cache_rule(
            ecrRepositoryPrefix=root_prefix,
            upstreamRegistryUrl=_UPSTREAM,
            upstreamRepositoryPrefix="docker",
        )
    )
    expected_duplicate = (
        "PullThroughCacheRuleAlreadyExistsException",
        f"A pull-through cache rule with repository prefix '{root_prefix}' already exists in the "
        f"registry with id '{ctx.account}'",
    )
    assert duplicate == expected_duplicate, f"expected {expected_duplicate!r}, got {duplicate!r}"
    unchanged = [
        _fields(r)
        for r in ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[root_prefix])[
            "pullThroughCacheRules"
        ]
    ]
    assert unchanged == [expected_root], (
        f"the refused duplicate must leave the rule as {expected_root!r}, got {unchanged!r}"
    )

    deleted = ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=named_prefix)
    assert _fields(deleted) == expected_named, (
        f"expected DeletePullThroughCacheRule to return {expected_named!r}, got {deleted!r}"
    )
    gone = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[named_prefix])
    )
    expected_gone = (
        "PullThroughCacheRuleNotFoundException",
        f"A pull-through cache rule with repository prefix '{named_prefix}' does not exist in the "
        f"registry with id '{ctx.account}'",
    )
    assert gone == expected_gone, f"expected {expected_gone!r}, got {gone!r}"
    update_on_dead = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=named_prefix,
            customRoleArn=f"arn:aws:iam::{ctx.account}:role/{named_prefix}-role",
        )
    )
    assert update_on_dead == expected_gone, (
        f"expected UpdatePullThroughCacheRule on a deleted prefix to fail the same way, "
        f"got {update_on_dead!r}"
    )
    remaining = [
        _fields(r)
        for r in ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[root_prefix])[
            "pullThroughCacheRules"
        ]
    ]
    assert remaining == [expected_root], (
        f"deleting the other rule must leave {expected_root!r} in place, got {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
