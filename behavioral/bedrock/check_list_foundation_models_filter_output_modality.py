"""list-foundation-models-filter-output-modality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-filter-output-modality"
GROUP = 'foundation_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFoundationModels with byOutputModality=TEXT returns exactly the model ids the
    unfiltered catalog lists with TEXT in outputModalities, no more and no fewer, and the catalog
    also holds non-TEXT models, so an ignored filter fails.
    """
    bc = ctx.client("bedrock")

    baseline = bc.list_foundation_models().get("modelSummaries", [])
    assert baseline, "the unfiltered foundation-model catalog must be non-empty"

    expected = {m["modelId"] for m in baseline if "TEXT" in (m.get("outputModalities") or [])}
    non_text = {m["modelId"] for m in baseline} - expected
    assert non_text, (
        "no non-TEXT-output model in the catalog to distinguish the filter from returning "
        "everything -- this check has no discriminating power in this account/region"
    )

    resp = bc.list_foundation_models(byOutputModality="TEXT")
    models = resp.get("modelSummaries", [])
    assert models, "No TEXT output modality models found"
    actual = {m["modelId"] for m in models}

    extra = actual - expected
    assert not extra, (
        f"byOutputModality=TEXT returned models the catalog's own metadata says are not "
        f"TEXT-capable: {sorted(extra)!r}"
    )
    missing = expected - actual
    assert not missing, (
        f"byOutputModality=TEXT omitted TEXT-capable models present in the unfiltered catalog: "
        f"{sorted(missing)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
