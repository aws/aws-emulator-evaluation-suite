"""validate-state-machine-definition-reports-errors."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-state-machine-definition-reports-errors"
GROUP = "server-side"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ValidateStateMachineDefinition performs server-side static analysis and returns
    structured diagnostics for a bad ASL definition, while a valid definition passes clean."""
    sfn = ctx.client("stepfunctions")

    # A definition whose StartAt references a state that doesn't exist in States - this is
    # a semantic ASL error that real AWS catches without ever creating a state machine.
    bad_definition = json.dumps(
        {
            "Comment": "sim2real-behav validation probe",
            "StartAt": "StateThatDoesNotExist",
            "States": {
                "OnlyRealState": {"Type": "Pass", "End": True},
            },
        }
    )

    bad_resp = sfn.validate_state_machine_definition(
        definition=bad_definition, severity="WARNING"
    )
    assert bad_resp["result"] == "FAIL", f"expected FAIL, got {bad_resp['result']}"
    diagnostics = bad_resp["diagnostics"]
    assert len(diagnostics) >= 1, "expected at least one diagnostic for a broken definition"
    error_diags = [d for d in diagnostics if d["severity"] == "ERROR"]
    assert error_diags, f"expected an ERROR-severity diagnostic, got {diagnostics}"
    for d in error_diags:
        assert d["code"], "diagnostic must carry a code"
        assert d["message"], "diagnostic must carry a message"

    # Sanity/contrast check: a syntactically and semantically valid single-state definition
    # must validate cleanly (result OK, no ERROR diagnostics) - proves the FAIL above is
    # actually about the broken reference and not a blanket rejection.
    good_definition = json.dumps(
        {
            "StartAt": "OnlyRealState",
            "States": {
                "OnlyRealState": {"Type": "Pass", "End": True},
            },
        }
    )
    good_resp = sfn.validate_state_machine_definition(definition=good_definition)
    assert good_resp["result"] == "OK", f"expected OK, got {good_resp}"
    good_errors = [d for d in good_resp["diagnostics"] if d["severity"] == "ERROR"]
    assert not good_errors, f"valid definition should have no ERROR diagnostics: {good_errors}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
