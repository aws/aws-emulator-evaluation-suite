"""get-control-parameter-requirement-invariant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-parameter-requirement-invariant"
GROUP = "data-plane"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For each listed control, GetControl's Parameters match its ParameterRequirementSummary: NONE is empty,
    REQUIRED holds a REQUIRED parameter, OPTIONAL is non-empty with no REQUIRED parameter."""
    cc = ctx.client("controlcatalog")
    controls = cc.list_controls(MaxResults=25).get("Controls", [])
    assert controls, "ListControls returned no controls to validate against"

    checked = 0
    for summary in controls:
        detail = cc.get_control(ControlArn=summary["Arn"])
        prs = detail.get("ParameterRequirementSummary")
        params = detail.get("Parameters") or []
        if prs == "NONE":
            assert params == [], f"{summary['Arn']}: NONE but Parameters={params}"
        elif prs == "REQUIRED":
            assert len(params) > 0, f"{summary['Arn']}: REQUIRED but Parameters is empty"
            assert any(p.get("Requirement") == "REQUIRED" for p in params), summary["Arn"]
        elif prs == "OPTIONAL":
            assert len(params) > 0, f"{summary['Arn']}: OPTIONAL but Parameters is empty"
            assert not any(p.get("Requirement") == "REQUIRED" for p in params), (
                f"{summary['Arn']}: OPTIONAL but a parameter is itself marked Requirement=REQUIRED: {params}"
            )
        else:
            continue
        checked += 1

    assert checked > 0, "no control in the sampled page carried a recognized ParameterRequirementSummary"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
