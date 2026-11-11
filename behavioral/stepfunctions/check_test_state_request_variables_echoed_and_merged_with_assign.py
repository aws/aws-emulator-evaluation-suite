"""test-state-request-variables-echoed-and-merged-with-assign."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-state-request-variables-echoed-and-merged-with-assign"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TestState `variables` request parameter is readable by the tested state's JSONata
    expressions, and is merged with any variable the state itself Assigns."""
    sfn = ctx.client("stepfunctions")

    read_only_definition = json.dumps(
        {
            "QueryLanguage": "JSONata",
            "Type": "Pass",
            "Output": {"seen": "{% $preset %}"},
        }
    )
    read_resp = sfn.test_state(
        definition=read_only_definition,
        input=json.dumps({}),
        variables=json.dumps({"preset": "hello"}),
        inspectionLevel="DEBUG",
    )
    assert read_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {read_resp}"
    assert json.loads(read_resp["output"]) == {"seen": "hello"}, (
        f"state did not see the request-supplied variable: {read_resp['output']!r}"
    )
    read_vars = json.loads(read_resp["inspectionData"]["variables"])
    assert read_vars == {"preset": "hello"}, (
        f"request-supplied variables not echoed in inspectionData: {read_vars!r}"
    )

    merge_definition = json.dumps(
        {
            "QueryLanguage": "JSONata",
            "Type": "Pass",
            "Assign": {"computed": "{% $preset & '-x' %}"},
            "Output": {"ok": True},
        }
    )
    merge_resp = sfn.test_state(
        definition=merge_definition,
        input=json.dumps({}),
        variables=json.dumps({"preset": "hello"}),
        inspectionLevel="DEBUG",
    )
    assert merge_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {merge_resp}"
    merged_vars = json.loads(merge_resp["inspectionData"]["variables"])
    assert merged_vars == {"computed": "hello-x", "preset": "hello"}, (
        f"Assign-ed and request-supplied variables did not merge: {merged_vars!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
