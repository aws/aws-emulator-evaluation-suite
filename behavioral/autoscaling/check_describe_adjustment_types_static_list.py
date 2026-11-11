"""describe-adjustment-types-static-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-adjustment-types-static-list"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAdjustmentTypes returns exactly the fixed, service-defined enumeration
    of scaling adjustment types (ChangeInCapacity, ExactCapacity, PercentChangeInCapacity)."""
    autoscaling = ctx.client("autoscaling")

    resp = autoscaling.describe_adjustment_types()
    types = [item["AdjustmentType"] for item in resp["AdjustmentTypes"]]

    expected = {"ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"}
    assert set(types) == expected, f"unexpected adjustment types: {types}"
    assert len(types) == len(expected), "duplicate entries in AdjustmentTypes"

    # Calling it again returns the identical fixed enumeration (order-independent).
    resp2 = autoscaling.describe_adjustment_types()
    types2 = {item["AdjustmentType"] for item in resp2["AdjustmentTypes"]}
    assert types2 == expected, f"AdjustmentTypes changed across repeated calls: {types2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
