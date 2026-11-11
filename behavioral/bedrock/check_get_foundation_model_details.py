"""get-foundation-model-details."""
from __future__ import annotations

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

CHECK = "get-foundation-model-details"
GROUP = 'foundation_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFoundationModel returns detailed info for a known model ID."""
    bc = ctx.client("bedrock")
    resp = bc.get_foundation_model(modelIdentifier=MODEL_ID)
    details = resp.get("modelDetails", {})
    assert details.get("modelId") == MODEL_ID, (
        f"Expected modelId={MODEL_ID}, got {details.get('modelId')}"
    )
    assert details.get("providerName") == "Moonshot AI", (
        f"Expected providerName='Moonshot AI', got {details.get('providerName')!r}"
    )
    assert details.get("modelName") == "Kimi K2.5", (
        f"Expected modelName='Kimi K2.5', got {details.get('modelName')!r}"
    )
    input_modalities = set(details.get("inputModalities", []))
    assert input_modalities == {"TEXT", "IMAGE"}, (
        f"Expected inputModalities={{'TEXT', 'IMAGE'}}, got {input_modalities}"
    )
    output_modalities = set(details.get("outputModalities", []))
    assert output_modalities == {"TEXT"}, (
        f"Expected outputModalities={{'TEXT'}}, got {output_modalities}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
