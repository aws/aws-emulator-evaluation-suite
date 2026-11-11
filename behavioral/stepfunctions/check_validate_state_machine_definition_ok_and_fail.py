"""validate-state-machine-definition-ok-and-fail."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-state-machine-definition-ok-and-fail"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ValidateStateMachineDefinition returns OK for a valid ASL doc and FAIL with diagnostics for a broken one.

    A StartAt pointing at a nonexistent state must produce result FAIL carrying at least
    one structured diagnostic, without creating any real resource.
    """
    sfn = ctx.client("stepfunctions")
    good_def = json.dumps(
        {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    )
    good = sfn.validate_state_machine_definition(definition=good_def)
    assert good["result"] == "OK", f"expected OK, got {good}"

    broken = json.dumps(
        {"Comment": "bad", "StartAt": "Missing", "States": {"Other": {"Type": "Pass", "End": True}}}
    )
    bad = sfn.validate_state_machine_definition(definition=broken)
    assert bad["result"] == "FAIL", f"expected FAIL for a StartAt pointing at a nonexistent state, got {bad}"
    diagnostics = bad.get("diagnostics", [])
    assert len(diagnostics) > 0, "FAIL result must include at least one diagnostic"
    named_missing_state = any("Missing" in d.get("message", "") for d in diagnostics)
    assert named_missing_state, (
        f"expected a diagnostic naming the dangling StartAt target 'Missing', got {diagnostics}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
