"""evaluate-mapping-template-syntax-error-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-syntax-error-fails"
GROUP = 'evaluate'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateMappingTemplate reports a VTL syntax error in the response's error field (HTTP 200, no
    ClientError), after a well-formed template on the same context renders cleanly."""
    svc = ctx.client("appsync")
    context = json.dumps({"arguments": {"id": "1"}})

    good = svc.evaluate_mapping_template(
        template="$util.toJson($context.arguments.id)", context=context
    )
    assert good.get("error") in (None, {}), f"positive control unexpectedly errored: {good}"
    assert json.loads(good["evaluationResult"]) == "1", good

    bad_template = "#if($context.arguments.id"  # unterminated directive
    resp = svc.evaluate_mapping_template(template=bad_template, context=context)
    error = resp.get("error") or {}
    assert error.get("message"), f"expected a VTL parse error message, got {resp}"
    assert not resp.get("evaluationResult"), (
        f"malformed VTL must not produce a usable evaluationResult: {resp}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
