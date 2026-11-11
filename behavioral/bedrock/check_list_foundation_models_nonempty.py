"""list-foundation-models-nonempty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-nonempty"
GROUP = 'foundation_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFoundationModels returns a non-empty list of models, each summary's
    modelArn is the regional foundation-model ARN of its own modelId, and the
    modelIds are unique."""
    bc = ctx.client("bedrock")
    resp = bc.list_foundation_models()
    models = resp["modelSummaries"]
    assert len(models) > 0, "ListFoundationModels returned no models"
    ids = [m["modelId"] for m in models]
    assert len(ids) == len(set(ids)), f"duplicate modelIds in ListFoundationModels: {sorted(ids)!r}"
    wrong = [
        (m["modelId"], m["modelArn"])
        for m in models
        if m["modelArn"] != f"arn:aws:bedrock:{ctx.region}::foundation-model/{m['modelId']}"
    ]
    assert wrong == [], f"modelArn does not match the regional ARN of its modelId: {wrong!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
