"""common-control-objective-reference-resolves."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "common-control-objective-reference-resolves"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every common control's associated Objective ARN resolves to a real entry in ListObjectives."""
    cc = ctx.client("controlcatalog")

    all_objective_arns: set[str] = set()
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_objectives(**kwargs)
        for objective in page.get("Objectives", []):
            all_objective_arns.add(objective["Arn"])
        token = page.get("NextToken")
        if not token:
            break
    assert all_objective_arns, "expected the Control Catalog to contain at least one objective"

    common_controls: list = []
    token = None
    for _ in range(30):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_common_controls(**kwargs)
        common_controls.extend(page.get("CommonControls", []))
        token = page.get("NextToken")
        if not token:
            break
    assert common_controls, "expected the Control Catalog to contain at least one common control"

    for common_control in common_controls:
        objective_arn = common_control["Objective"]["Arn"]
        assert objective_arn in all_objective_arns, (
            f"common control {common_control['Arn']} references objective {objective_arn} "
            "which is absent from ListObjectives"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
