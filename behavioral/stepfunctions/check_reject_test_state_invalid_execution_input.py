"""reject-test-state-invalid-execution-input."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "reject-test-state-invalid-execution-input"
GROUP = "overly-permissive"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState with execution input that isn't valid JSON returns
    InvalidExecutionInput rather than running the state with garbage input."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    definition = json.dumps({"Type": "Pass", "End": True})

    code = message = None
    try:
        sfn.test_state(definition=definition, input="this is definitely not { json")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")

    assert code is not None, "TestState with malformed JSON input unexpectedly succeeded"
    assert code == "InvalidExecutionInput", f"expected InvalidExecutionInput, got {code}"
    expected = (
        "Invalid State Machine Execution Input: 'Unrecognized token 'this': was expecting "
        "(JSON String, Number, Array, Object or token 'null', 'true' or 'false')'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Sanity: the same state definition with valid JSON input runs to completion.
    good_resp = sfn.test_state(definition=definition, input=json.dumps({"a": 1}))
    assert good_resp["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED with valid input, got {good_resp.get('status')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
