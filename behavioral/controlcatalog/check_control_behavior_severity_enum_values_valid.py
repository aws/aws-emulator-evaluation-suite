"""control-behavior-severity-enum-values-valid."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-behavior-severity-enum-values-valid"
GROUP = "data-plane"
SERVICES = ["controlcatalog"]

_BEHAVIORS = {"PREVENTIVE", "PROACTIVE", "DETECTIVE"}
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_PARAM_REQS = {"REQUIRED", "OPTIONAL", "NONE"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every returned control's Behavior/Severity/ParameterRequirementSummary use documented enum values."""
    cc = ctx.client("controlcatalog")
    controls = cc.list_controls(MaxResults=100).get("Controls", [])
    assert controls, "ListControls returned no controls"

    for c in controls:
        behavior = c.get("Behavior")
        if behavior is not None:
            assert behavior in _BEHAVIORS, f"{c['Arn']}: unexpected Behavior {behavior!r}"
        severity = c.get("Severity")
        if severity is not None:
            assert severity in _SEVERITIES, f"{c['Arn']}: unexpected Severity {severity!r}"
        prs = c.get("ParameterRequirementSummary")
        if prs is not None:
            assert prs in _PARAM_REQS, f"{c['Arn']}: unexpected ParameterRequirementSummary {prs!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
