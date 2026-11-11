"""test-state-assign-rejected-on-succeed-and-fail."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-assign-rejected-on-succeed-and-fail"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]

_EXPECTED_MESSAGE = (
    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Field 'Assign' is not "
    "supported at /States/StateName'"
)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    because accepting a refused input must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the definition to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState rejects an Assign field on a Succeed or a Fail state with InvalidDefinition and
    the API's own exact message, while the identical state without Assign succeeds."""
    sfn = ctx.client("stepfunctions")

    succeed_with_assign = json.dumps(
        {"QueryLanguage": "JSONata", "Type": "Succeed", "Assign": {"x": 1}}
    )
    code, message = _error(lambda: sfn.test_state(definition=succeed_with_assign, input="{}"))
    assert code == "InvalidDefinition", f"Succeed+Assign: expected InvalidDefinition, got {code}"
    assert message == _EXPECTED_MESSAGE, f"Succeed+Assign: unexpected message {message!r}"

    fail_with_assign = json.dumps(
        {
            "QueryLanguage": "JSONata",
            "Type": "Fail",
            "Assign": {"x": 1},
            "Error": "E",
            "Cause": "C",
        }
    )
    code, message = _error(lambda: sfn.test_state(definition=fail_with_assign, input="{}"))
    assert code == "InvalidDefinition", f"Fail+Assign: expected InvalidDefinition, got {code}"
    assert message == _EXPECTED_MESSAGE, f"Fail+Assign: unexpected message {message!r}"

    # Positive control: the same two state types, without Assign, both succeed.
    succeed_control = sfn.test_state(
        definition=json.dumps({"QueryLanguage": "JSONata", "Type": "Succeed", "Output": {"done": True}}),
        input="{}",
    )
    assert succeed_control["status"] == "SUCCEEDED", (
        f"Succeed positive control did not succeed: {succeed_control!r}"
    )

    fail_control = sfn.test_state(
        definition=json.dumps({"Type": "Fail", "Error": "E", "Cause": "C"}), input="{}"
    )
    assert fail_control["status"] == "FAILED", (
        f"Fail positive control did not reach FAILED: {fail_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
