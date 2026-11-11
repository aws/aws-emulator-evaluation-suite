"""describe-termination-policy-types-static-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-termination-policy-types-static-list"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTerminationPolicyTypes returns every well-known, service-defined
    termination policy type usable in UpdateAutoScalingGroup's TerminationPolicies
    parameter, each exactly once."""
    autoscaling = ctx.client("autoscaling")

    resp = autoscaling.describe_termination_policy_types()
    types = resp["TerminationPolicyTypes"]

    expected = {
        "OldestInstance",
        "OldestLaunchConfiguration",
        "NewestInstance",
        "ClosestToNextInstanceHour",
        "Default",
        "OldestLaunchTemplate",
        "AllocationStrategy",
        "Lambda",
    }
    assert set(types) >= expected, (
        f"missing termination policy types {expected - set(types)} in {types}"
    )
    assert len(types) == len(set(types)), f"duplicate entries in TerminationPolicyTypes: {types}"

    # "Default" must be one of the valid TerminationPolicies values accepted elsewhere.
    assert "Default" in types, f"'Default' missing from TerminationPolicyTypes: {types}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
