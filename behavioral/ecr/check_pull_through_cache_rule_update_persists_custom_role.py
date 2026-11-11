"""pull-through-cache-rule-update-persists-custom-role."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pull-through-cache-rule-update-persists-custom-role"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom role ARN set via UpdatePullThroughCacheRule persists and is returned by
    DescribePullThroughCacheRules, entirely replacing the original creation-time value
    (not merged/appended alongside it)."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    prefix = ctx.unique_name("sim2real-behav-")

    original_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-ptcrole-original"
    updated_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-ptcrole-updated"
    upstream_url = "111122223333.dkr.ecr.us-east-1.amazonaws.com"

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="ecr",
        upstreamRegistryUrl=upstream_url,
        customRoleArn=original_role_arn,
    )
    ctx.on_cleanup(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix))

    created = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ][0]
    assert created["customRoleArn"] == original_role_arn, (
        f"expected creation-time customRoleArn {original_role_arn!r}, "
        f"got {created.get('customRoleArn')!r}"
    )

    ecr.update_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, customRoleArn=updated_role_arn
    )

    updated = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])[
        "pullThroughCacheRules"
    ][0]
    assert updated["customRoleArn"] == updated_role_arn, (
        f"customRoleArn was not replaced: expected {updated_role_arn!r}, "
        f"got {updated.get('customRoleArn')!r}"
    )
    assert updated["customRoleArn"] != original_role_arn, (
        f"customRoleArn still equals the original {original_role_arn!r} after update; "
        "the update did not take effect"
    )
    assert updated["ecrRepositoryPrefix"] == prefix, (
        f"expected ecrRepositoryPrefix {prefix!r}, got {updated.get('ecrRepositoryPrefix')!r}"
    )
    assert updated["upstreamRegistryUrl"] == created["upstreamRegistryUrl"], (
        f"unrelated field upstreamRegistryUrl changed across the customRoleArn-only update: "
        f"before {created['upstreamRegistryUrl']!r}, after {updated.get('upstreamRegistryUrl')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
