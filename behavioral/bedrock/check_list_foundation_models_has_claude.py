"""list-foundation-models-has-claude."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-has-claude"
GROUP = 'foundation_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFoundationModels includes at least one Anthropic Claude model, and byProvider is a
    real filter rather than an accepted-and-ignored parameter."""
    bc = ctx.client("bedrock")
    resp = bc.list_foundation_models(byProvider="Anthropic")
    models = resp.get("modelSummaries", [])
    assert len(models) > 0, "No Anthropic models found in ListFoundationModels"
    model_ids = [m["modelId"] for m in models]
    has_claude = any("claude" in mid for mid in model_ids)
    assert has_claude, f"No Claude model found. Model IDs: {model_ids[:5]}"

    # Negative control: without this, a target that ignores byProvider and always returns the
    # whole catalog would still pass the assertions above. Pick a non-Anthropic provider that the
    # unfiltered catalog itself reports (never hardcoded) and confirm filtering by it excludes
    # every Claude model.
    baseline = bc.list_foundation_models().get("modelSummaries", [])
    other_providers = sorted(
        {m.get("providerName") for m in baseline if m.get("providerName") not in (None, "Anthropic")}
    )
    assert other_providers, "No non-Anthropic provider found in the catalog to use as a control"
    other = other_providers[0]
    other_ids = [m["modelId"] for m in bc.list_foundation_models(byProvider=other).get("modelSummaries", [])]
    assert other_ids, f"byProvider={other!r} returned no models"
    assert not any("claude" in mid for mid in other_ids), (
        f"byProvider={other!r} returned a Claude model ({other_ids}); byProvider is not "
        f"excluding Anthropic's models"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
