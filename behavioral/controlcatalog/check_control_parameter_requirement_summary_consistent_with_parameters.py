"""control-parameter-requirement-summary-consistent-with-parameters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-parameter-requirement-summary-consistent-with-parameters"
GROUP = "semantics"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A control's ParameterRequirementSummary matches its Parameters: NONE has none, REQUIRED has a parameter
    with Requirement=REQUIRED, OPTIONAL has named parameters none of which is REQUIRED."""
    cc = ctx.client("controlcatalog")
    page = cc.list_controls(MaxResults=50)
    controls = page["Controls"]
    assert len(controls) > 0, f"ListControls returned no controls: {page}"

    checked_none = False
    checked_required = False
    checked_optional = False
    for c in controls:
        got = cc.get_control(ControlArn=c["Arn"])
        summary = got.get("ParameterRequirementSummary")
        params = got.get("Parameters") or []
        if summary == "NONE":
            assert params == [], f"NONE summary but Parameters non-empty on {c['Arn']}: {params}"
            checked_none = True
        elif summary in ("REQUIRED", "OPTIONAL"):
            assert len(params) > 0, f"{summary} summary but Parameters empty on {c['Arn']}"
            for p in params:
                assert p.get("Name"), f"parameter without a Name on {c['Arn']}: {p}"
            has_required_param = any(p.get("Requirement") == "REQUIRED" for p in params)
            if summary == "REQUIRED":
                assert has_required_param, (
                    f"REQUIRED summary but no parameter individually marked REQUIRED on "
                    f"{c['Arn']}: {params}"
                )
                checked_required = True
            else:
                assert not has_required_param, (
                    f"OPTIONAL summary but a parameter is individually marked REQUIRED on "
                    f"{c['Arn']}: {params}"
                )
                checked_optional = True

    assert checked_none and (checked_required or checked_optional), (
        f"parameter-requirement invariant under-exercised: none={checked_none} "
        f"required={checked_required} optional={checked_optional}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
