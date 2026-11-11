"""quota-share-weight-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "quota-share-weight-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fractional fair-share weightFactor (12.375) round-trips through DescribeSchedulingPolicies
    without rounding; QuotaShare itself has only integer capacity fields, so weightFactor is the
    fractional share weight. 12.375 is binary-exact, so float conversion cannot make it flaky.
    """
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sched-policy-")
    weight = 12.375

    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 10,
            "shareDecaySeconds": 0,
            "shareDistribution": [{"shareIdentifier": "teamA", "weightFactor": weight}],
        },
        tags={"env": "sim2real-behav"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    described = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]
    assert len(described) == 1, f"expected exactly one scheduling policy for {arn}, got {described}"
    distribution = described[0]["fairsharePolicy"]["shareDistribution"]
    matches = [d for d in distribution if d["shareIdentifier"] == "teamA"]
    assert len(matches) == 1, f"expected exactly one shareDistribution entry, got {distribution}"
    got = matches[0]["weightFactor"]
    assert got == weight, f"weightFactor round-tripped as {got!r}, expected exactly {weight!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
