"""control-severity-and-behavior-enum-values-valid."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-severity-and-behavior-enum-values-valid"
GROUP = "semantics"
SERVICES = ["controlcatalog"]

_VALID_BEHAVIORS = {"PREVENTIVE", "PROACTIVE", "DETECTIVE"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every control's Behavior is a required, real ControlBehavior enum value and every present
    Severity is a real ControlSeverity enum value -- both from ListControls summaries and from
    GetControl -- rather than a raw passthrough string or an empty placeholder."""
    cc = ctx.client("controlcatalog")
    page = cc.list_controls(MaxResults=100)
    controls = page["Controls"]
    assert len(controls) > 0, "expected at least one control in the catalog"

    for c in controls:
        assert c.get("Behavior") in _VALID_BEHAVIORS, f"unexpected Behavior {c.get('Behavior')!r} on {c['Arn']}"
        severity = c.get("Severity")
        if severity is not None:
            assert severity in _VALID_SEVERITIES, f"unexpected Severity {severity!r} on {c['Arn']}"

    reference = controls[0]
    got = cc.get_control(ControlArn=reference["Arn"])
    assert got["Behavior"] in _VALID_BEHAVIORS, f"unexpected Behavior {got['Behavior']!r} on {reference['Arn']}"
    if got.get("Severity") is not None:
        assert got["Severity"] in _VALID_SEVERITIES, f"unexpected Severity {got['Severity']!r} on {reference['Arn']}"
    # Enum membership alone cannot detect a target that reports a different-but-still-valid
    # value between the two operations, so pin GetControl to agree with the ListControls entry
    # it was resolved from.
    assert got["Behavior"] == reference.get("Behavior"), (
        f"Behavior mismatch for {reference['Arn']}: GetControl {got['Behavior']!r} != ListControls {reference.get('Behavior')!r}"
    )
    assert got.get("Severity") == reference.get("Severity"), (
        f"Severity mismatch for {reference['Arn']}: GetControl {got.get('Severity')!r} != ListControls {reference.get('Severity')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
