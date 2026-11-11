"""describe-nonexistent-group-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-nonexistent-group-returns-empty"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAutoScalingGroups for an unknown name returns an empty list, not an error."""
    as_ = ctx.client("autoscaling")
    bogus = ctx.unique_name("sim2real-behav-as-missing-")
    resp = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[bogus])
    assert resp["AutoScalingGroups"] == [], "unknown group name must yield empty list, no exception"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
