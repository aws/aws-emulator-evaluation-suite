"""detect-entities-scores-within-valid-range."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-scores-within-valid-range"
GROUP = "invariant"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """All confidence scores returned by DetectEntitiesV2 are real probabilities in [0, 1]."""
    cm = ctx.client("comprehendmedical")
    text = (
        "The 68-year-old male patient was prescribed 10 mg of lisinopril once daily for "
        "hypertension and denies any history of diabetes."
    )
    resp = cm.detect_entities_v2(Text=text)
    entities = resp["Entities"]
    assert len(entities) > 0, "expected at least one entity to validate scores against"

    scores_checked = 0
    all_scores = []
    for entity in entities:
        assert 0.0 <= entity["Score"] <= 1.0, f"entity Score out of range: {entity}"
        all_scores.append(entity["Score"])
        scores_checked += 1
        for attribute in entity.get("Attributes", []):
            assert 0.0 <= attribute["Score"] <= 1.0, f"attribute Score out of range: {attribute}"
            assert 0.0 <= attribute["RelationshipScore"] <= 1.0, f"attribute RelationshipScore out of range: {attribute}"
            all_scores.append(attribute["Score"])
            all_scores.append(attribute["RelationshipScore"])
            scores_checked += 1
        for trait in entity.get("Traits", []):
            assert 0.0 <= trait["Score"] <= 1.0, f"trait Score out of range: {trait}"
            all_scores.append(trait["Score"])
            scores_checked += 1

    assert scores_checked > 1, "expected multiple scored fields to have been validated"

    distinct = {round(s, 6) for s in all_scores}
    assert len(distinct) > 1, (
        f"all {len(all_scores)} scored fields returned the identical value {all_scores[0]!r} -- "
        f"a real confidence model varies its score per field; scores={all_scores}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
