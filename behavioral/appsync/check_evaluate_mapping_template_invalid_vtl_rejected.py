"""evaluate-mapping-template-invalid-vtl-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-invalid-vtl-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

VALID_TEMPLATE = "$util.toJson($context.arguments.msg)"
BROKEN_TEMPLATE = "#if($context.arguments.msg"  # unterminated #if directive


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateMappingTemplate renders a valid VTL template, and for an unterminated #if returns HTTP
    200 with error.message and no evaluationResult rather than raising."""
    appsync = ctx.client("appsync")
    context = json.dumps({"arguments": {"msg": "well-formed"}})

    ok = appsync.evaluate_mapping_template(template=VALID_TEMPLATE, context=context)
    assert ok.get("error") is None, ok.get("error")
    assert json.loads(ok["evaluationResult"]) == "well-formed", ok

    resp = appsync.evaluate_mapping_template(template=BROKEN_TEMPLATE, context=context)
    error = resp.get("error") or {}
    assert error.get("message"), f"expected a VTL parse error message, got {resp}"
    assert not resp.get("evaluationResult"), (
        f"malformed VTL must not produce a usable evaluationResult: {resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
