"""test-state-pass-next-and-end-together-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-pass-next-and-end-together-rejected"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _error(fn):
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _definition(*, both: bool) -> str:
    """A full two-state machine whose terminal state carries End, and also Next when
    ``both`` is set."""
    last: dict = {"Type": "Pass", "End": True}
    if both:
        last["Next"] = "First"
    return json.dumps(
        {
            "StartAt": "First",
            "States": {
                "First": {"Type": "Pass", "Next": "Last"},
                "Last": last,
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState refuses a full definition whose stateName-selected state carries both Next
    and End with the exact schema message naming that state's path, and creates no
    resources; the same state with End alone succeeds and passes its input through."""
    sfn = ctx.client("stepfunctions")
    test_input = json.dumps({"k": "v"})

    code, message = _error(
        lambda: sfn.test_state(definition=_definition(both=True), stateName="Last", input=test_input)
    )
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code}: {message!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: There should only be one "
        "of the following fields: [Next, End] at /States/Last'"
    ), f"unexpected SCHEMA_VALIDATION_FAILED message: {message!r}"

    control = sfn.test_state(definition=_definition(both=False), stateName="Last", input=test_input)
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"
    assert json.loads(control["output"]) == {"k": "v"}, (
        f"positive control must pass its input through unchanged, got {control['output']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
