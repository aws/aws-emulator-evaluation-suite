"""reject-validate-definition-catches-invalid-asl."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "reject-validate-definition-catches-invalid-asl"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ValidateStateMachineDefinition flags structurally invalid ASL (unknown
    state Type, no terminating End/Next) rather than reporting it as valid."""
    sfn = ctx.client("stepfunctions")

    bad_definition = json.dumps(
        {
            "StartAt": "Bogus",
            "States": {
                "Bogus": {
                    "Type": "NotARealStateType",
                    "Comment": "invalid type and no End/Next",
                }
            },
        }
    )
    bad_resp = sfn.validate_state_machine_definition(definition=bad_definition)
    assert bad_resp["result"] == "FAIL", f"expected FAIL, got {bad_resp['result']}"
    diagnostics = bad_resp.get("diagnostics", [])
    assert len(diagnostics) > 0, "expected at least one diagnostic for invalid ASL"
    error_diags = [d for d in diagnostics if d.get("severity") == "ERROR"]
    assert error_diags, f"expected at least one ERROR-severity diagnostic, got {diagnostics}"
    for d in error_diags:
        assert d.get("code"), f"expected a non-empty diagnostic code, got {d}"
        assert d.get("message"), f"expected a non-empty diagnostic message, got {d}"

    # Sanity: a genuinely valid definition must report OK with no ERROR diagnostics.
    good_definition = json.dumps(
        {"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
    )
    good_resp = sfn.validate_state_machine_definition(definition=good_definition)
    assert good_resp["result"] == "OK", f"expected OK, got {good_resp['result']}"
    good_errors = [
        d for d in good_resp.get("diagnostics", []) if d.get("severity") == "ERROR"
    ]
    assert not good_errors, f"valid definition should have no ERROR diagnostics: {good_errors}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
