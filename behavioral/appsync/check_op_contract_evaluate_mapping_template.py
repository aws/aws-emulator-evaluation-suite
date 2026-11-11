"""op-contract-evaluateMappingTemplate."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-evaluateMappingTemplate"
GROUP = "error-semantics"
SERVICES = ["appsync"]

_GOOD_TEMPLATE = "$util.toJson($context.arguments)"
_BAD_TEMPLATE = "#if($context.arguments.id == '1')\n$util.toJson($context.arguments)"  # missing #end


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateMappingTemplate: success contract (VTL render) + a structured error field on a parse error."""
    appsync = ctx.client("appsync")
    context = json.dumps({"arguments": {"id": "widget-1"}})

    resp = appsync.evaluate_mapping_template(template=_GOOD_TEMPLATE, context=context)
    assert resp.get("error") in (None, {}), f"unexpected evaluation error: {resp.get('error')}"
    result = json.loads(resp["evaluationResult"])
    assert result == {"id": "widget-1"}, f"unexpected evaluationResult: {result}"

    # Error boundary: an unbalanced #if directive fails VTL parsing. EvaluateMappingTemplate
    # reports this through the structured error field of a 200 response (like $util.error()),
    # not as an HTTP-level ClientError -- so assert on resp["error"], not an exception.
    bad_resp = appsync.evaluate_mapping_template(template=_BAD_TEMPLATE, context=context)
    error = bad_resp.get("error") or {}
    assert error, f"expected a VTL parse error, got: {bad_resp}"
    message = error.get("message") or ""
    assert "ParseErrorException" in message, (
        f"expected a Velocity parse-error message for the unbalanced #if, got: {error}"
    )
    assert not bad_resp.get("evaluationResult"), (
        f"evaluationResult should be empty on a parse error: {bad_resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
