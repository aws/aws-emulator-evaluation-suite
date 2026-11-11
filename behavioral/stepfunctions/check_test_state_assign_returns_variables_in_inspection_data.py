"""test-state-assign-returns-variables-in-inspection-data."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-state-assign-returns-variables-in-inspection-data"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState on a JSONata state with Assign returns the assigned variables in
    inspectionData.variables at DEBUG level; INFO (the default) omits inspectionData."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps(
        {
            "QueryLanguage": "JSONata",
            "Type": "Pass",
            "Assign": {"orderId": "{% $states.input.id %}", "factor": 3},
            "Output": {"ok": True},
        }
    )
    test_input = json.dumps({"id": "abc"})

    debug_resp = sfn.test_state(definition=definition, input=test_input, inspectionLevel="DEBUG")
    assert debug_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {debug_resp}"
    variables = json.loads(debug_resp["inspectionData"]["variables"])
    assert variables == {"orderId": "abc", "factor": 3}, (
        f"Assign-ed variables not reflected in inspectionData: {variables!r}"
    )

    info_resp = sfn.test_state(definition=definition, input=test_input, inspectionLevel="INFO")
    assert info_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {info_resp}"
    assert "inspectionData" not in info_resp, (
        f"INFO inspection level must omit inspectionData entirely, got {info_resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
