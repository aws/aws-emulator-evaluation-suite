"""list-foundation-models-filters-exclude-non-matching."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-filters-exclude-non-matching"
GROUP = 'foundation_models'
SERVICES = ['bedrock']


# ListFoundationModels is unpaginated, so one call per filter sees the whole result.
# (request kwarg, summary field the filter must agree with, value); byProvider is discovered.
_MULTI_VALUE_FILTERS = (
    ("byOutputModality", "outputModalities", "EMBEDDING"),
    ("byOutputModality", "outputModalities", "IMAGE"),
    ("byInferenceType", "inferenceTypesSupported", "PROVISIONED"),
    ("byCustomizationType", "customizationsSupported", "FINE_TUNING"),
)


def _ids(resp):
    """modelId set from a ListFoundationModels response, asserting the required members exist."""
    summaries = resp.get("modelSummaries")
    assert summaries is not None, (
        f"ListFoundationModels must return modelSummaries; got keys {sorted(resp)!r}"
    )
    out = set()
    for s in summaries:
        # modelArn and modelId are @required on FoundationModelSummary.
        assert s.get("modelId"), f"FoundationModelSummary.modelId is required; got {s!r}"
        assert s.get("modelArn"), f"FoundationModelSummary.modelArn is required; got {s!r}"
        out.add(s["modelId"])
    return out


def _expected(summaries, field, value):
    """Model ids whose own unfiltered metadata lists `value` in `field`."""
    return {s["modelId"] for s in summaries if value in (s.get(field) or [])}


def _assert_filter(actual, expected, baseline, label):
    assert actual <= baseline, (
        f"{label} returned model ids absent from the unfiltered catalog: "
        f"{sorted(actual - baseline)!r}"
    )
    assert actual == expected, (
        f"{label} disagrees with the catalog's own per-model metadata. "
        f"Returned-but-non-matching: {sorted(actual - expected)!r}; "
        f"matching-but-omitted: {sorted(expected - actual)!r}. "
        f"(An emulator that accepts the filter parameter and ignores it returns the whole "
        f"catalog and shows up as returned-but-non-matching.)"
    )


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFoundationModels filters exclude non-matching models, matching the unfiltered metadata.

    Expected sets come from the unfiltered catalog itself, so no model list is pinned; filters that
    match none or all models are skipped, and the check fails if no filter discriminates.
    """
    bc = ctx.client("bedrock")

    baseline_resp = bc.list_foundation_models()
    summaries = baseline_resp["modelSummaries"]
    baseline = _ids(baseline_resp)
    assert baseline, "the unfiltered foundation-model catalog must be non-empty"

    graded = []

    for param, field, value in _MULTI_VALUE_FILTERS:
        expected = _expected(summaries, field, value)
        if not expected or expected == baseline:
            # No discriminating power in this region/account: either nothing matches or everything
            # does, so the filter being ignored would be indistinguishable from it working.
            continue
        actual = _ids(bc.list_foundation_models(**{param: value}))
        _assert_filter(actual, expected, baseline, f"{param}={value}")
        graded.append(f"{param}={value}")

    # byProvider: pick a provider that owns some but not all of the catalog, discovered from the
    # catalog itself so no provider name is hard-coded.
    providers = {}
    for s in summaries:
        name = s.get("providerName")
        if name:
            providers.setdefault(name, set()).add(s["modelId"])
    for name, ids in sorted(providers.items()):
        if not ids or ids == baseline:
            continue
        actual = _ids(bc.list_foundation_models(byProvider=name))
        _assert_filter(actual, ids, baseline, f"byProvider={name}")
        graded.append(f"byProvider={name}")
        break

    if not graded:
        raise AssertionError(
            "no ListFoundationModels filter had discriminating power in this catalog: every "
            f"candidate filter matched either none or all of the {len(baseline)} models, so "
            "passing would be vacuous. This is itself a signal that the catalog is degenerate."
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
