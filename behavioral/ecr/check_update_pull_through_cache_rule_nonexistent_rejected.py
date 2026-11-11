"""update-pull-through-cache-rule-nonexistent-rejected."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "update-pull-through-cache-rule-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule on a never-registered prefix is refused
    PullThroughCacheRuleNotFoundException with the exact message and creates no rule, while the
    registered rule updates and stays the one rule for its prefix."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ecr.meta.region_name
    # A customRoleArn is accepted only on an "ecr" upstream in another account and another region,
    # named by its full private-registry host and given with upstreamRepositoryPrefix.
    upstream_region = "us-east-1" if region != "us-east-1" else "us-west-2"
    foreign_account_id = "111111111111" if account_id != "111111111111" else "222222222222"
    upstream_url = f"{foreign_account_id}.dkr.ecr.{upstream_region}.amazonaws.com"
    real_prefix = _prefix_name(ctx, "real")
    missing_prefix = _prefix_name(ctx, "missing")

    initial_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-uptcr-role-a-')}"
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=real_prefix,
        upstreamRegistry="ecr",
        upstreamRegistryUrl=upstream_url,
        upstreamRepositoryPrefix=real_prefix,
        customRoleArn=initial_role_arn,
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, real_prefix))

    # Positive control: updating the rule that actually exists succeeds.
    ok_resp = ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=real_prefix, customRoleArn=f"arn:aws:iam::{account_id}:role/sim2real-ok"
    )
    assert ok_resp["ecrRepositoryPrefix"] == real_prefix, (
        f"expected update response to echo {real_prefix!r}, got {ok_resp.get('ecrRepositoryPrefix')!r}"
    )

    code, message = _error(
        lambda: ecr.update_pull_through_cache_rule(
            ecrRepositoryPrefix=missing_prefix,
            customRoleArn=f"arn:aws:iam::{account_id}:role/sim2real-missing",
        )
    )
    assert code == "PullThroughCacheRuleNotFoundException", (
        f"expected PullThroughCacheRuleNotFoundException, got {code!r}"
    )
    expected_message = (
        f"A pull-through cache rule with repository prefix '{missing_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # The rejected call must not have disturbed the unrelated, genuinely configured rule.
    real_rules = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[real_prefix])[
        "pullThroughCacheRules"
    ]
    assert len(real_rules) == 1, (
        f"expected the real rule for {real_prefix!r} to still be present, got {real_rules!r}"
    )
    not_found_code, not_found_message = _error(
        lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[missing_prefix])
    )
    assert not_found_code == "PullThroughCacheRuleNotFoundException", (
        f"expected the rejected update to leave {missing_prefix!r} unregistered "
        f"(PullThroughCacheRuleNotFoundException), got {not_found_code!r}"
    )
    expected_not_found_message = (
        f"A pull-through cache rule with repository prefix '{missing_prefix}' does not exist "
        f"in the registry with id '{ctx.account}'"
    )
    assert not_found_message == expected_not_found_message, (
        f"expected the exact refusal message {expected_not_found_message!r}, got {not_found_message!r}"
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
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
