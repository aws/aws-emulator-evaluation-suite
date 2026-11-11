"""list-foundation-models-filters-compose-as-conjunction."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-foundation-models-filters-compose-as-conjunction"
GROUP = "foundation_models"
SERVICES = ["bedrock"]

# (request kwarg, summary/detail field, filter value).
_LIST_FILTERS = (
    ("byOutputModality", "outputModalities", "TEXT"),
    ("byOutputModality", "outputModalities", "IMAGE"),
    ("byOutputModality", "outputModalities", "EMBEDDING"),
    ("byInferenceType", "inferenceTypesSupported", "ON_DEMAND"),
    ("byInferenceType", "inferenceTypesSupported", "PROVISIONED"),
    ("byCustomizationType", "customizationsSupported", "FINE_TUNING"),
    ("byCustomizationType", "customizationsSupported", "CONTINUED_PRE_TRAINING"),
)

_MAX_DETAIL_LOOKUPS = 5


def _ids(resp):
    """The modelId set from a ListFoundationModels response, asserting the @required members."""
    summaries = resp.get("modelSummaries")
    assert summaries is not None, (
        f"ListFoundationModels must return modelSummaries; got keys {sorted(resp)!r}"
    )
    out = set()
    for s in summaries:
        assert s.get("modelId"), f"FoundationModelSummary.modelId is required; got {s!r}"
        assert s.get("modelArn"), f"FoundationModelSummary.modelArn is required; got {s!r}"
        out.add(s["modelId"])
    return out


def _matches(entry, field, value):
    """True when this model's own metadata reports `value` for `field` (scalar or list).

    An absent field is False: a model with no customization types omits `customizationsSupported`.
    """
    if field not in entry:
        return False
    held = entry[field]
    if isinstance(held, list):
        return value in held
    return held == value


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two ListFoundationModels filters together return the intersection of each alone, and
    GetFoundationModel confirms both attributes on included models and denies one on an excluded one.
    """
    bc = ctx.client("bedrock")

    baseline_resp = bc.list_foundation_models()
    summaries = baseline_resp["modelSummaries"]
    baseline = _ids(baseline_resp)
    assert baseline, "the unfiltered foundation-model catalog must be non-empty"

    # Candidate predicates: the four modelled list filters over values the catalog actually uses,
    # plus every provider that owns a strict subset of the catalog.
    candidates = []
    for param, field, value in _LIST_FILTERS:
        ids = {s["modelId"] for s in summaries if value in (s.get(field) or [])}
        if ids and ids != baseline:
            candidates.append((param, field, value, ids))
    providers = {}
    for s in summaries:
        name = s.get("providerName")
        if name:
            providers.setdefault(name, set()).add(s["modelId"])
    for name, ids in sorted(providers.items()):
        if ids and ids != baseline:
            candidates.append(("byProvider", "providerName", name, ids))

    # A usable pair: the intersection must be non-empty AND strictly smaller than each side, so that
    # "first filter only", "second filter only" and "union" all give a different answer from the
    # conjunction. Without that, an ignored parameter would be invisible.
    pair = None
    for i, left in enumerate(candidates):
        for right in candidates[i + 1:]:
            if left[0] == right[0] and left[1] == right[1]:
                continue  # two values of the same repeated filter is a different question
            inter = left[3] & right[3]
            if inter and inter != left[3] and inter != right[3]:
                pair = (left, right, inter)
                break
        if pair:
            break

    # A degenerate catalog raises rather than passing vacuously.
    if pair is None:
        raise AssertionError(
            "no pair of ListFoundationModels filters in this catalog has discriminating power: "
            "every candidate intersection was empty or equal to one of its sides, so an ignored "
            f"filter parameter would be invisible. Catalog size {len(baseline)}, "
            f"{len(candidates)} candidate filters. A degenerate catalog is itself a fidelity signal."
        )

    (p_param, p_field, p_value, p_ids), (q_param, q_field, q_value, q_ids), expected = pair
    label = f"{p_param}={p_value} + {q_param}={q_value}"

    actual = _ids(bc.list_foundation_models(**{p_param: p_value, q_param: q_value}))
    assert actual <= baseline, (
        f"{label} returned model ids absent from the unfiltered catalog: "
        f"{sorted(actual - baseline)!r}"
    )
    assert actual == expected, (
        f"{label} must return the INTERSECTION the catalog's own metadata predicts. "
        f"Returned-but-non-matching: {sorted(actual - expected)!r}; matching-but-omitted: "
        f"{sorted(expected - actual)!r}. Single-filter sizes were {len(p_ids)} and {len(q_ids)}, "
        f"intersection {len(expected)}, union {len(p_ids | q_ids)} -- an emulator honouring only "
        f"one parameter returns one of the single-filter sizes, and one that disjoins returns the "
        f"union."
    )

    # Cross-check against GetFoundationModel, a different operation from the listing.
    for model_id in sorted(expected)[:_MAX_DETAIL_LOOKUPS]:
        details = bc.get_foundation_model(modelIdentifier=model_id)["modelDetails"]
        assert details.get("modelId") == model_id, (
            f"GetFoundationModel must echo the requested modelIdentifier {model_id!r}; got "
            f"{details.get('modelId')!r}"
        )
        assert _matches(details, p_field, p_value), (
            f"{model_id!r} was returned under {label} but its own GetFoundationModel record does "
            f"not report {p_field}={p_value!r}; details={details!r}"
        )
        assert _matches(details, q_field, q_value), (
            f"{model_id!r} was returned under {label} but its own GetFoundationModel record does "
            f"not report {q_field}={q_value!r}; details={details!r}"
        )

    # ...and the exclusion direction, on the same independent operation: a model that matched only
    # the first filter must deny the second attribute in its own detail record.
    excluded_id = sorted(p_ids - expected)[0]
    excluded = bc.get_foundation_model(modelIdentifier=excluded_id)["modelDetails"]
    assert not _matches(excluded, q_field, q_value), (
        f"{excluded_id!r} was excluded from {label} yet its own GetFoundationModel record claims "
        f"{q_field}={q_value!r}, so the listing and the detail record disagree; details={excluded!r}"
    )
    assert excluded_id not in actual, (
        f"{excluded_id!r} lacks {q_field}={q_value!r} and must not appear under {label}; got "
        f"{sorted(actual)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
