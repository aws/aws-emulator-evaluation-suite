"""evaluate-mapping-template-success."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-success"
GROUP = "evaluate"
SERVICES = ["appsync"]

# Prefix of the failure detail raised when EvaluateMappingTemplate does not render the VTL: a target
# with no template engine refuses the call or returns nothing, and that is a data-plane miss, not a
# connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateMappingTemplate renders VTL against the supplied context and returns the transformed payload."""
    svc = ctx.client("appsync")
    template = "$util.toJson($context.arguments)"
    context = json.dumps({"arguments": {"id": "abc-123"}})

    try:
        resp = svc.evaluate_mapping_template(template=template, context=context)
    except ClientError as exc:
        # The VTL engine IS the data plane: a target that cannot render refuses rather than
        # answering wrongly, and that refusal is the fidelity verdict.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: evaluate_mapping_template refused: {exc}"
        ) from exc
    assert resp.get("error") in (None, {}), f"{DATAPLANE_MARKER}: {resp.get('error')}"

    raw = resp.get("evaluationResult")
    assert raw, f"{DATAPLANE_MARKER}: no evaluationResult returned: {resp!r}"
    # No marker here on purpose: a rendered-but-WRONG payload means the engine ran, which is an
    # ordinary fidelity failure rather than an absent data plane.
    result = json.loads(raw)
    assert result == {"id": "abc-123"}, result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
