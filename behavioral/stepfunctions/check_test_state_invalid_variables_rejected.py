"""test-state-invalid-variables-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-invalid-variables-rejected"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    because accepting a refused input must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState rejects a malformed `variables` request parameter — invalid JSON, a non-object
    value, or an object key that is not a valid variable name — with ValidationException and the
    API's own exact message, while a well-formed `variables` value succeeds."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps({"QueryLanguage": "JSONata", "Type": "Pass", "Output": {"ok": True}})

    code, message = _error(
        lambda: sfn.test_state(definition=definition, input="{}", variables='{"preset": "X1"')
    )
    assert code == "ValidationException", f"malformed JSON: expected ValidationException, got {code}"
    assert message == "The value of 'variables' is not valid JSON.", (
        f"malformed JSON: unexpected message {message!r}"
    )

    code, message = _error(
        lambda: sfn.test_state(
            definition=definition, input="{}", variables=json.dumps({"1bad": "x"})
        )
    )
    assert code == "ValidationException", f"invalid name: expected ValidationException, got {code}"
    assert message == "Invalid variable name '1bad': the variable name contains invalid characters.", (
        f"invalid name: unexpected message {message!r}"
    )

    code, message = _error(
        lambda: sfn.test_state(definition=definition, input="{}", variables=json.dumps([1, 2, 3]))
    )
    assert code == "ValidationException", f"non-object: expected ValidationException, got {code}"
    assert message == "The value of 'variables' must be a valid JSON object.", (
        f"non-object: unexpected message {message!r}"
    )

    # Positive control: a well-formed variables object succeeds.
    control = sfn.test_state(
        definition=definition, input="{}", variables=json.dumps({"good_name": "x"})
    )
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
