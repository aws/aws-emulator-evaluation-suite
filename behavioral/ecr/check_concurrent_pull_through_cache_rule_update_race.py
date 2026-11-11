"""concurrent-pull-through-cache-rule-update-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-pull-through-cache-rule-update-race"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdatePullThroughCacheRule calls on the same prefix, each setting a
    different customRoleArn, do not corrupt the rule: the final DescribePullThroughCacheRules
    reflects exactly one complete writer's value, not an interleaved/partial state."""
    ecr = ctx.client("ecr")
    prefix = ctx.unique_name("sim2real-behav-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    upstream_url = "111122223333.dkr.ecr.us-east-1.amazonaws.com"

    role_initial = f"arn:aws:iam::{account_id}:role/sim2real-behav-ptcr-role-initial"
    role_a = f"arn:aws:iam::{account_id}:role/sim2real-behav-ptcr-role-a"
    role_b = f"arn:aws:iam::{account_id}:role/sim2real-behav-ptcr-role-b"

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix,
        upstreamRegistry="ecr",
        upstreamRegistryUrl=upstream_url,
        customRoleArn=role_initial,
    )
    ctx.on_cleanup(lambda: ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(
            ecr.update_pull_through_cache_rule,
            ecrRepositoryPrefix=prefix,
            customRoleArn=role_a,
        )
        fut_b = pool.submit(
            ecr.update_pull_through_cache_rule,
            ecrRepositoryPrefix=prefix,
            customRoleArn=role_b,
        )
        fut_a.result()
        fut_b.result()

    described = ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix])
    rules = described["pullThroughCacheRules"]
    assert len(rules) == 1, f"expected exactly 1 rule for prefix, found {len(rules)}"
    rule = rules[0]

    assert rule["ecrRepositoryPrefix"] == prefix, (
        f"expected ecrRepositoryPrefix {prefix!r}, got {rule.get('ecrRepositoryPrefix')!r}"
    )
    assert rule["customRoleArn"] in (role_a, role_b), (
        f"customRoleArn is neither writer's value (and not the stale initial value either): "
        f"{rule.get('customRoleArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
