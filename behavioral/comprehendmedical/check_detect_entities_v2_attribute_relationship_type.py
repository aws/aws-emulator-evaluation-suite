"""detect-entities-v2-attribute-relationship-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-entities-v2-attribute-relationship-type"
GROUP = "invoke"
SERVICES = ["comprehendmedical"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectEntitiesV2 tags a medication's DOSAGE attribute with a matching RelationshipType."""
    cm = ctx.client("comprehendmedical")
    text = "The patient was prescribed 200 mg of ibuprofen twice daily for pain relief."
    resp = cm.detect_entities_v2(Text=text)
    entities = resp["Entities"]

    medication = next(
        (e for e in entities if e["Category"] == "MEDICATION" and "ibuprofen" in e["Text"].lower()),
        None,
    )
    assert medication is not None, f"no MEDICATION entity for ibuprofen found in {entities}"

    dosage_attr = next((a for a in medication.get("Attributes", []) if a["Type"] == "DOSAGE"), None)
    assert dosage_attr is not None, f"expected a DOSAGE attribute on {medication}"
    assert dosage_attr["RelationshipType"] == "DOSAGE", (
        f"expected RelationshipType DOSAGE, got {dosage_attr['RelationshipType']!r} on {dosage_attr}"
    )
    assert 0.0 <= dosage_attr["RelationshipScore"] <= 1.0, (
        f"RelationshipScore out of [0,1]: {dosage_attr['RelationshipScore']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
