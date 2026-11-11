"""test-state-invalid-definition-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-invalid-definition-rejected"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState with malformed JSON as the definition fails with InvalidDefinition "The state definition
    must be valid JSON", while a valid single-state definition SUCCEEDS with output {"ok": true}."""
    sfn = ctx.client("stepfunctions")

    good_definition = json.dumps({"Type": "Pass", "Result": {"ok": True}, "End": True})
    control = sfn.test_state(definition=good_definition, input="{}")
    assert control["status"] == "SUCCEEDED", f"positive control did not succeed: {control!r}"
    assert json.loads(control["output"]) == {"ok": True}, (
        f"positive control returned unexpected output: {control!r}"
    )

    malformed_definition = '{"Type": "Pass", "End": true'  # missing closing brace
    error = _client_error(lambda: sfn.test_state(definition=malformed_definition, input="{}"))
    assert error.get("Code") == "InvalidDefinition", (
        f"expected InvalidDefinition, got {error.get('Code')!r}: {error!r}"
    )
    assert error.get("Message") == "The state definition must be valid JSON", (
        f"unexpected InvalidDefinition message: {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
