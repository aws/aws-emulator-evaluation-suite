"""test-state-statename-selects-succeed-state-jsonata-output."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-state-statename-selects-succeed-state-jsonata-output"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _definition(*, top_level_jsonata: bool) -> str:
    """A full two-state machine whose Succeed state has a JSONata Output expression,
    set either by the top-level QueryLanguage or by the state's own."""
    succeed_state = {"Type": "Succeed", "Output": "{% $states.input.value * 2 %}"}
    if top_level_jsonata:
        top = {"QueryLanguage": "JSONata"}
    else:
        top = {}
        succeed_state["QueryLanguage"] = "JSONata"
    return json.dumps(
        {
            **top,
            "StartAt": "First",
            "States": {
                "First": {"Type": "Pass", "Next": "Last"},
                "Last": succeed_state,
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState with stateName picks one state out of a full state machine definition; a
    Succeed state's JSONata Output expression is evaluated the same whether QueryLanguage is
    set at the top level of the definition or on the state itself."""
    sfn = ctx.client("stepfunctions")
    test_input = json.dumps({"value": 21})

    top_level_resp = sfn.test_state(
        definition=_definition(top_level_jsonata=True), stateName="Last", input=test_input
    )
    assert top_level_resp["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED with top-level QueryLanguage, got {top_level_resp!r}"
    )
    assert json.loads(top_level_resp["output"]) == 42, (
        f"expected the Output expression evaluated to 42, got {top_level_resp['output']!r}"
    )

    state_level_resp = sfn.test_state(
        definition=_definition(top_level_jsonata=False), stateName="Last", input=test_input
    )
    assert state_level_resp["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED with state-level QueryLanguage, got {state_level_resp!r}"
    )
    assert json.loads(state_level_resp["output"]) == 42, (
        f"expected the Output expression evaluated to 42, got {state_level_resp['output']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
