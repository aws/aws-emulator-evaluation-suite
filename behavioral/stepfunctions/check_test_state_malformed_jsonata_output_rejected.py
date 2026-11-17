"""test-state-malformed-jsonata-output-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-malformed-jsonata-output-rejected"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict, raising if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _definition(output_expr: str) -> str:
    return json.dumps(
        {
            "QueryLanguage": "JSONata",
            "StartAt": "First",
            "States": {
                "First": {"Type": "Pass", "Next": "Last"},
                "Last": {"Type": "Succeed", "Output": output_expr},
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState on a Succeed state whose JSONata Output expression does not parse fails with
    InvalidDefinition naming INVALID_JSONATA_EXPRESSION and the field's location; a well-formed
    Output expression on the same state SUCCEEDS with the evaluated result."""
    sfn = ctx.client("stepfunctions")
    test_input = json.dumps({"value": 21})

    malformed = _definition("{% $states.input.value * %}")
    error = _client_error(
        lambda: sfn.test_state(definition=malformed, stateName="Last", input=test_input)
    )
    assert error.get("Code") == "InvalidDefinition", (
        f"expected InvalidDefinition, got {error.get('Code')!r}: {error!r}"
    )
    assert error.get("Message") == (
        "Invalid State Machine Definition: 'INVALID_JSONATA_EXPRESSION: Unexpected end of "
        "expression at /States/Last/Output'"
    ), f"unexpected InvalidDefinition message: {error.get('Message')!r}"

    well_formed = _definition("{% $states.input.value * 2 %}")
    control = sfn.test_state(definition=well_formed, stateName="Last", input=test_input)
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"
    assert json.loads(control["output"]) == 42, (
        f"positive control returned unexpected output: {control['output']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
