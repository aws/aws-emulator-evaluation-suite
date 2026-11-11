"""detect-entities-negation-trait-detected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-negation-trait-detected"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntitiesV2 tags an explicitly denied condition with a NEGATION trait, and does not
    apply that same trait to the identical condition when it is affirmed rather than denied --
    a target that tags NEGATION on every entity indiscriminately must not pass this."""
    cm = ctx.client("comprehendmedical")

    def chest_pain_traits(text: str) -> set[str]:
        resp = cm.detect_entities_v2(Text=text)
        entities = resp["Entities"]
        chest_pain = next(
            (e for e in entities if e["Category"] == "MEDICAL_CONDITION" and "chest pain" in e["Text"].lower()),
            None,
        )
        assert chest_pain is not None, f"no chest pain MEDICAL_CONDITION entity found in {entities}"
        return {t["Name"] for t in chest_pain.get("Traits", [])}

    negated_traits = chest_pain_traits("Patient denies any chest pain or shortness of breath.")
    assert "NEGATION" in negated_traits, f"expected a NEGATION trait, got {negated_traits}"

    affirmed_traits = chest_pain_traits("Patient reports chest pain and shortness of breath.")
    assert "NEGATION" not in affirmed_traits, (
        f"chest pain is affirmed, not denied, but was tagged NEGATION: {affirmed_traits}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
