"""validate-state-machine-definition-invalid-type-value-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-state-machine-definition-invalid-type-value-rejected"
GROUP = "errors"
SERVICES = ["stepfunctions"]


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateStateMachineDefinition with a type value outside STANDARD/EXPRESS ->
    ValidationException naming the enum; a valid type still validates the definition."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})

    # --- Negative: a type value outside the StateMachineType enum -> ValidationException.
    code, message = _error(
        lambda: sfn.validate_state_machine_definition(definition=definition, type="BOGUS")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'BOGUS' at 'type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [EXPRESS, STANDARD]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Positive control: an explicit, valid enum value still validates cleanly.
    good_resp = sfn.validate_state_machine_definition(definition=definition, type="EXPRESS")
    assert good_resp["result"] == "OK", f"expected OK, got {good_resp['result']!r}"
    good_errors = [d for d in good_resp.get("diagnostics", []) if d.get("severity") == "ERROR"]
    assert not good_errors, f"valid definition should have no ERROR diagnostics: {good_errors}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
