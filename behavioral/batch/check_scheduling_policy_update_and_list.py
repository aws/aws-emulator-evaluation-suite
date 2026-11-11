"""scheduling-policy-update-and-list."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "scheduling-policy-update-and-list"
GROUP = 'scheduling-policy'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _create_scheduling_policy(ctx, bat, name=None, fairshare_policy=None):
    name = name or ctx.unique_name("sim2real-behav-sp-")
    resp = bat.create_scheduling_policy(
        name=name,
        fairsharePolicy=fairshare_policy
        or {"computeReservation": 0, "shareDecaySeconds": 0, "shareDistribution": []},
        tags={"env": "sim2real-behav"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_scheduling_policy(arn=arn)))
    return name, arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedulingPolicy rewrites the fairshare policy and ListSchedulingPolicies sees it."""
    bat = ctx.client("batch")
    _name, arn = _create_scheduling_policy(
        ctx,
        bat,
        fairshare_policy={
            "computeReservation": 10,
            "shareDecaySeconds": 60,
            "shareDistribution": [{"shareIdentifier": "teamA", "weightFactor": 1.0}],
        },
    )

    pol = bat.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert pol["fairsharePolicy"]["computeReservation"] == 10, (
        f"expected computeReservation 10, got {pol['fairsharePolicy']['computeReservation']!r}"
    )
    assert pol["fairsharePolicy"]["shareDecaySeconds"] == 60, (
        f"expected shareDecaySeconds 60, got {pol['fairsharePolicy']['shareDecaySeconds']!r}"
    )

    bat.update_scheduling_policy(
        arn=arn,
        fairsharePolicy={
            "computeReservation": 25,
            "shareDecaySeconds": 120,
            "shareDistribution": [
                {"shareIdentifier": "teamA", "weightFactor": 2.0},
                {"shareIdentifier": "teamB", "weightFactor": 4.0},
            ],
        },
    )

    pol = bat.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    fs = pol["fairsharePolicy"]
    assert fs["computeReservation"] == 25, f"expected computeReservation 25, got {fs['computeReservation']!r}"
    assert fs["shareDecaySeconds"] == 120, f"expected shareDecaySeconds 120, got {fs['shareDecaySeconds']!r}"
    weights = {s["shareIdentifier"]: s["weightFactor"] for s in fs["shareDistribution"]}
    assert weights == {"teamA": 2.0, "teamB": 4.0}, f"share distribution not replaced: {weights}"

    arns = {p["arn"] for p in bat.list_scheduling_policies()["schedulingPolicies"]}
    assert arn in arns, "ListSchedulingPolicies must include the created policy"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
