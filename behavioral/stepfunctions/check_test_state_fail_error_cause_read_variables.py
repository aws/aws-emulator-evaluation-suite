"""test-state-fail-error-cause-read-variables."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-state-fail-error-cause-read-variables"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState on a JSONata Fail state evaluates Error/Cause expressions against the
    request-supplied `variables`, and the response's error/cause fields carry the result."""
    sfn = ctx.client("stepfunctions")
    definition = json.dumps(
        {
            "QueryLanguage": "JSONata",
            "Type": "Fail",
            "Error": "{% 'ErrorFor-' & $preset %}",
            "Cause": "{% 'CauseFor-' & $preset %}",
        }
    )
    resp = sfn.test_state(
        definition=definition,
        input=json.dumps({}),
        variables=json.dumps({"preset": "X1"}),
    )
    assert resp["status"] == "FAILED", f"expected FAILED, got {resp}"
    assert resp["error"] == "ErrorFor-X1", f"Error expression did not read $preset: {resp!r}"
    assert resp["cause"] == "CauseFor-X1", f"Cause expression did not read $preset: {resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
