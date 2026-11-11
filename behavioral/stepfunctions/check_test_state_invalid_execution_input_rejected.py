"""test-state-invalid-execution-input-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-invalid-execution-input-rejected"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_MALFORMED_INPUT_MESSAGE = (
    "Invalid State Machine Execution Input: 'Unexpected end-of-input: expected close marker for "
    "Object (start marker at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` "
    "disabled); line: 1, column: 1])'"
)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises, because a
    target accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState with malformed JSON as the input fails with InvalidExecutionInput and the exact message,
    while the same Pass definition with valid input SUCCEEDS and echoes it ({"probe": 1})."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps({"Type": "Pass", "End": True})

    control = sfn.test_state(definition=definition, input=json.dumps({"probe": 1}))
    assert control["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {control}"
    assert json.loads(control["output"]) == {"probe": 1}, f"expected echoed input, got {control['output']}"

    malformed_input = '{"probe": 1'  # missing closing brace
    code, message = _error(lambda: sfn.test_state(definition=definition, input=malformed_input))
    assert code == "InvalidExecutionInput", f"expected InvalidExecutionInput, got {code}"
    assert message == _MALFORMED_INPUT_MESSAGE, f"unexpected InvalidExecutionInput message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
