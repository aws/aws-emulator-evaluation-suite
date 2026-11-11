"""op-contract-describeSchedulingPolicies."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeSchedulingPolicies"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSchedulingPolicies returns the exact fairsharePolicy configuration for a
    created policy; a nonexistent ARN mixed into the request is silently omitted from the
    response rather than causing the whole call to fail."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    resp = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 25,
            "shareDecaySeconds": 300,
            "shareDistribution": [
                {"shareIdentifier": "teamA", "weightFactor": 1.0},
                {"shareIdentifier": "teamB", "weightFactor": 2.5},
            ],
        },
        tags={"team": "sim2real", "purpose": "behavioral-check"},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    described = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"]
    assert len(described) == 1, f"expected exactly 1 policy for {arn}, got {len(described)}"
    policy = described[0]
    assert policy["name"] == name, f"expected name {name!r}, got {policy['name']!r}"
    assert policy["fairsharePolicy"]["computeReservation"] == 25, policy["fairsharePolicy"]
    assert policy["fairsharePolicy"]["shareDecaySeconds"] == 300, policy["fairsharePolicy"]
    shares = {sd["shareIdentifier"]: sd["weightFactor"] for sd in policy["fairsharePolicy"]["shareDistribution"]}
    assert shares == {"teamA": 1.0, "teamB": 2.5}, shares

    # Error boundary: a nonexistent (but well-formed) ARN mixed into the request does not
    # fail the whole call -- the real service just omits it and returns only the known policy.
    fake_arn = arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-batch-sp-missing-")
    mixed = batch.describe_scheduling_policies(arns=[arn, fake_arn])["schedulingPolicies"]
    names_returned = {p["name"] for p in mixed}
    assert names_returned == {name}, (
        f"expected only the real policy for a mixed real/fake arns request, got {names_returned}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
