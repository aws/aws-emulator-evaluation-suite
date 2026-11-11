"""list-foundation-models-model-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-model-fields"
GROUP = 'foundation_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each model summary contains required fields: modelId, modelName, providerName."""
    bc = ctx.client("bedrock")
    resp = bc.list_foundation_models()
    models = resp.get("modelSummaries", [])
    assert models, f"ListFoundationModels returned no model summaries; got response keys {sorted(resp)!r}"
    for m in models:
        assert "modelId" in m, f"modelId missing from summary: {m}"
        assert "modelName" in m, f"modelName missing from summary: {m}"
        assert "providerName" in m, f"providerName missing from summary: {m}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
