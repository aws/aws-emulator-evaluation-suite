"""pull-through-cache-rule-update-round-trip."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "pull-through-cache-rule-update-round-trip"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePullThroughCacheRule on an ecr-upstream rule replaces its customRoleArn, echoed by
    the update and returned by DescribePullThroughCacheRules with an updatedAt not before
    createdAt."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ecr.meta.region_name
    # A customRoleArn is accepted only on an "ecr" upstream in another account and another region,
    # named by its full private-registry host and given with upstreamRepositoryPrefix.
    upstream_region = "us-east-1" if region != "us-east-1" else "us-west-2"
    foreign_account_id = "111111111111" if account_id != "111111111111" else "222222222222"
    upstream_url = f"{foreign_account_id}.dkr.ecr.{upstream_region}.amazonaws.com"
    prefix = _prefix_name(ctx, "ptc")

    initial_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ptcr-role-a-')}"
    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="ecr",
        upstreamRegistryUrl=upstream_url,
        upstreamRepositoryPrefix=prefix,
        customRoleArn=initial_role_arn,
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, prefix))

    before = _describe_one(ecr, prefix)
    assert before.get("customRoleArn") == initial_role_arn, (
        f"expected the just-created rule to report customRoleArn={initial_role_arn!r}, "
        f"got {before.get('customRoleArn')!r}"
    )

    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-ptcr-role-b-')}"
    update_resp = ecr.update_pull_through_cache_rule(ecrRepositoryPrefix=prefix, customRoleArn=role_arn)
    assert update_resp["ecrRepositoryPrefix"] == prefix, (
        f"expected UpdatePullThroughCacheRule to echo ecrRepositoryPrefix={prefix!r}, "
        f"got {update_resp['ecrRepositoryPrefix']!r}"
    )
    assert update_resp["customRoleArn"] == role_arn, (
        f"expected UpdatePullThroughCacheRule to echo customRoleArn={role_arn!r}, "
        f"got {update_resp['customRoleArn']!r}"
    )

    after = _describe_one(ecr, prefix)
    assert after["customRoleArn"] == role_arn, (
        f"expected the independent describe read to reflect customRoleArn={role_arn!r} "
        f"after update, got {after['customRoleArn']!r}"
    )
    assert after["updatedAt"] >= before["createdAt"], (
        f"expected updatedAt ({after['updatedAt']!r}) to not precede createdAt "
        f"({before['createdAt']!r})"
    )


def _prefix_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real{kind}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return raw[:28] if raw else f"sim2real{kind}"


def _describe_one(ecr, prefix: str) -> dict:
    rules = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ]
    assert len(rules) == 1, f"expected exactly one rule for {prefix}, got {rules}"
    return rules[0]


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
