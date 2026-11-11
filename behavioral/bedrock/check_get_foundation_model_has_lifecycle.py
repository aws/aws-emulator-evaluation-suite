"""get-foundation-model-has-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

CHECK = "get-foundation-model-has-lifecycle"
GROUP = 'foundation_models'
SERVICES = ['bedrock']


def _assert_lifecycle_consistent(model_id, lifecycle):
    assert "status" in lifecycle, (
        f"modelLifecycle.status missing from GetFoundationModel({model_id!r}). "
        f"Got keys: {list(lifecycle.keys())}"
    )
    status = lifecycle["status"]
    assert status in ("ACTIVE", "LEGACY"), (
        f"Unexpected lifecycle status for {model_id!r}: {status!r}"
    )
    assert "startOfLifeTime" in lifecycle, (
        f"modelLifecycle.startOfLifeTime missing for {model_id!r} (status={status!r})"
    )
    if status == "ACTIVE":
        assert "legacyTime" not in lifecycle, (
            f"ACTIVE model {model_id!r} has legacyTime set: {lifecycle.get('legacyTime')!r}"
        )
        assert "endOfLifeTime" not in lifecycle, (
            f"ACTIVE model {model_id!r} has endOfLifeTime set: {lifecycle.get('endOfLifeTime')!r}"
        )
    else:
        assert "legacyTime" in lifecycle, (
            f"LEGACY model {model_id!r} is missing legacyTime"
        )
        assert "endOfLifeTime" in lifecycle, (
            f"LEGACY model {model_id!r} is missing endOfLifeTime"
        )


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFoundationModel's modelLifecycle status is consistent with its own time fields, for both an ACTIVE and a LEGACY model."""
    bc = ctx.client("bedrock")

    resp = bc.get_foundation_model(modelIdentifier=MODEL_ID)
    details = resp.get("modelDetails", {})
    _assert_lifecycle_consistent(MODEL_ID, details.get("modelLifecycle", {}))

    summaries = bc.list_foundation_models().get("modelSummaries", [])
    legacy_summary = next(
        (m for m in summaries if m.get("modelLifecycle", {}).get("status") == "LEGACY"), None
    )
    assert legacy_summary is not None, (
        "no LEGACY-status model found in ListFoundationModels; cannot confirm the LEGACY branch "
        f"(checked {len(summaries)} models)"
    )
    legacy_id = legacy_summary["modelId"]
    legacy_details = bc.get_foundation_model(modelIdentifier=legacy_id).get("modelDetails", {})
    _assert_lifecycle_consistent(legacy_id, legacy_details.get("modelLifecycle", {}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
