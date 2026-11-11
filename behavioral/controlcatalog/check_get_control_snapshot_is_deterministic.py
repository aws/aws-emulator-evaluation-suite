"""get-control-snapshot-is-deterministic."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-snapshot-is-deterministic"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two GetControl calls for the same control ARN return byte-identical non-volatile fields."""
    cc = ctx.client("controlcatalog")
    controls = cc.list_controls(MaxResults=1).get("Controls", [])
    assert controls, "expected the Control Catalog to contain at least one control"
    arn = controls[0]["Arn"]

    first = cc.get_control(ControlArn=arn)
    second = cc.get_control(ControlArn=arn)

    non_volatile_fields = (
        "Arn",
        "Name",
        "Description",
        "Behavior",
        "Severity",
        "ParameterRequirementSummary",
        "Parameters",
        "GovernedResources",
        "GovernedProviders",
        "Aliases",
        "RegionConfiguration",
        "Implementation",
        "CreateTime",
    )
    for field in non_volatile_fields:
        assert first.get(field) == second.get(field), f"field {field} differs between identical GetControl calls"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
